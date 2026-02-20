package main

import (
	"container/heap"
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// ----- CONFIG -----

type Config struct {
	MongoURI       string
	DBName         string
	JWTSecret      []byte
	Port           string
	WorkerCount    int
	JobWaitSeconds time.Duration
	AdminUsernames []string
	AdminEnvUser   string
	AdminEnvPass   string
}

var cfg Config
var mongoClient *mongo.Client
var db *mongo.Database

func loadConfig() error {
	_ = godotenv.Load()

	cfg.MongoURI = os.Getenv("MONGO_URI")
	if cfg.MongoURI == "" {
		return errors.New("MONGO_URI is required")
	}

	secret := os.Getenv("JWT_SECRET_KEY")
	if secret == "" {
		return errors.New("JWT_SECRET_KEY is required")
	}
	cfg.JWTSecret = []byte(secret)

	cfg.DBName = os.Getenv("MONGO_DBNAME")
	if cfg.DBName == "" {
		cfg.DBName = "twomanga"
	}

	cfg.Port = os.Getenv("PORT")
	if cfg.Port == "" {
		cfg.Port = "5001"
	}

	wc, err := strconv.Atoi(os.Getenv("WORKER_COUNT"))
	if err != nil || wc <= 0 {
		wc = 4
	}
	cfg.WorkerCount = wc

	ws, err := strconv.ParseFloat(os.Getenv("JOB_WAIT_SECONDS"), 64)
	if err != nil || ws <= 0 {
		ws = 8.0
	}
	cfg.JobWaitSeconds = time.Duration(ws * float64(time.Second))

	admins := os.Getenv("ADMIN_USERNAMES")
	for _, u := range strings.Split(admins, ",") {
		if t := strings.TrimSpace(u); t != "" {
			cfg.AdminUsernames = append(cfg.AdminUsernames, strings.ToLower(t))
		}
	}
	cfg.AdminEnvUser = strings.ToLower(os.Getenv("ADMIN_USERNAME"))
	cfg.AdminEnvPass = os.Getenv("ADMIN_PASSWORD")

	return nil
}

// ----- DATABASE -----

func connectDB(ctx context.Context) error {
	if cfg.MongoURI == "" {
		return errors.New("mongo uri empty")
	}

	clientOptions := options.Client().ApplyURI(cfg.MongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return err
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return err
	}

	mongoClient = client
	db = client.Database(cfg.DBName)
	log.Printf("Connected to MongoDB: %s", cfg.DBName)
	return nil
}

func getDB() (*mongo.Database, error) {
	if db == nil {
		return nil, errors.New("database not initialized")
	}
	return db, nil
}

// ----- MODELS -----

type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username       string             `bson:"username" json:"username"`
	Password       string             `bson:"password" json:"-"`
	Role           string             `bson:"role" json:"role"`
	SessionSalt    string             `bson:"session_salt" json:"-"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	TotalPurchases int                `bson:"total_purchases" json:"total_purchases"`
	ExpiryDate     *time.Time         `bson:"expiryDate,omitempty" json:"expiryDate,omitempty"`
}

type Coupon struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Code      string               `bson:"code" json:"code"`
	BonusDays int                  `bson:"bonus_days" json:"bonus_days"`
	MaxUses   *int                 `bson:"max_uses" json:"max_uses"`
	Uses      int                  `bson:"uses" json:"uses"`
	UsedBy    []primitive.ObjectID `bson:"used_by" json:"used_by"`
	ExpiresAt *time.Time           `bson:"expires_at" json:"expires_at"`
	CreatedAt time.Time            `bson:"created_at" json:"created_at"`
}

type Transaction struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       primitive.ObjectID `bson:"user_id" json:"user_id"`
	Username     string             `bson:"username" json:"username"`
	TxHash       string             `bson:"tx_hash" json:"tx_hash"`
	Days         int                `bson:"days" json:"days"`
	Status       string             `bson:"status" json:"status"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	ProcessedAt  *time.Time         `bson:"processed_at,omitempty" json:"processed_at,omitempty"`
	ApprovedBy   string             `bson:"approved_by,omitempty" json:"approved_by,omitempty"`
	RejectedAt   *time.Time         `bson:"rejected_at,omitempty" json:"rejected_at,omitempty"`
	RejectedBy   string             `bson:"rejected_by,omitempty" json:"rejected_by,omitempty"`
	RejectReason string             `bson:"reject_reason,omitempty" json:"reject_reason,omitempty"`
}

// ----- UTILS -----

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ----- WORKER ENGINE (Priority Queue) -----

type JobResult struct {
	Data interface{}
	Err  error
	Code int
}

type Job struct {
	Priority   int
	Sequence   int64
	Func       func() (interface{}, int, error)
	ResultChan chan JobResult
}

type PriorityQueue []*Job

func (pq PriorityQueue) Len() int { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool {
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority
	}
	return pq[i].Sequence < pq[j].Sequence
}
func (pq PriorityQueue) Swap(i, j int)       { pq[i], pq[j] = pq[j], pq[i] }
func (pq *PriorityQueue) Push(x interface{}) { *pq = append(*pq, x.(*Job)) }
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

var (
	jobQueue   = make(PriorityQueue, 0)
	queueLock  sync.Mutex
	jobSignal  = make(chan struct{}, 1000)
	shutdownCh = make(chan struct{})
	wg         sync.WaitGroup
)

func SubmitJob(priority int, task func() (interface{}, int, error), wait bool) (interface{}, int, error) {
	resChan := make(chan JobResult, 1)
	job := &Job{
		Priority:   priority,
		Sequence:   time.Now().UnixNano(),
		Func:       task,
		ResultChan: resChan,
	}

	queueLock.Lock()
	heap.Push(&jobQueue, job)
	queueLock.Unlock()

	select {
	case jobSignal <- struct{}{}:
	default:
	}

	if !wait {
		return map[string]interface{}{"queued": true, "job_id": job.Sequence}, 202, nil
	}

	select {
	case res := <-resChan:
		return res.Data, res.Code, res.Err
	case <-time.After(cfg.JobWaitSeconds):
		return map[string]string{"msg": "Processing queued due to load"}, 202, nil
	case <-shutdownCh:
		return map[string]string{"msg": "Server shutting down"}, 503, nil
	}
}

func startWorkers(count int) {
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Worker-%d recovered from panic: %v", id, r)
				}
			}()
			log.Printf("Worker-%d started", id)
			for {
				select {
				case <-shutdownCh:
					log.Printf("Worker-%d stopping (shutdown)", id)
					return
				case <-jobSignal:
					queueLock.Lock()
					if jobQueue.Len() == 0 {
						queueLock.Unlock()
						continue
					}
					item := heap.Pop(&jobQueue).(*Job)
					queueLock.Unlock()

					func(j *Job) {
						defer func() {
							if r := recover(); r != nil {
								log.Printf("Worker-%d task panic recovered: %v", id, r)
								select {
								case j.ResultChan <- JobResult{Data: map[string]string{"msg": "Internal panic"}, Err: errors.New("task panic"), Code: 500}:
								default:
								}
							}
							close(j.ResultChan)
						}()

						data, code, err := j.Func()
						if err != nil && data == nil {
							data = map[string]string{"msg": "Internal Error", "detail": err.Error()}
							if code == 0 {
								code = 500
							}
						}
						select {
						case j.ResultChan <- JobResult{Data: data, Code: code, Err: err}:
						default:
						}
					}(item)
				}
			}
		}(i)
	}
}

// ----- BUSINESS LOGIC (Worker Side) -----

func logicApplyPayment(userIDStr string, couponCode, txHash string, daysReq int) (interface{}, int, error) {
	database, err := getDB()
	if err != nil {
		return nil, 500, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	userOID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		return map[string]string{"msg": "Invalid user id"}, 400, nil
	}

	var user User
	if err := database.Collection("users").FindOne(ctx, bson.M{"_id": userOID}).Decode(&user); err != nil {
		if err == mongo.ErrNoDocuments {
			return map[string]string{"msg": "User not found"}, 404, nil
		}
		return nil, 500, err
	}

	if couponCode != "" {
		couponColl := database.Collection("coupons")
		var cp Coupon
		err := couponColl.FindOne(ctx, bson.M{"code": couponCode}).Decode(&cp)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return map[string]string{"msg": "Invalid coupon code"}, 400, nil
			}
			return nil, 500, err
		}

		now := time.Now().UTC()
		if cp.ExpiresAt != nil && cp.ExpiresAt.Before(now) {
			_, _ = couponColl.DeleteOne(ctx, bson.M{"_id": cp.ID})
			return map[string]string{"msg": "Coupon expired"}, 400, nil
		}
		if cp.MaxUses != nil && cp.Uses >= *cp.MaxUses {
			_, _ = couponColl.DeleteOne(ctx, bson.M{"_id": cp.ID})
			return map[string]string{"msg": "Coupon limits reached"}, 400, nil
		}
		for _, uID := range cp.UsedBy {
			if uID == userOID {
				return map[string]string{"msg": "You have already used this coupon"}, 400, nil
			}
		}

		filter := bson.M{
			"_id":     cp.ID,
			"uses":    cp.Uses,
			"used_by": bson.M{"$ne": userOID},
		}
		update := bson.M{
			"$inc":  bson.M{"uses": 1},
			"$push": bson.M{"used_by": userOID},
		}

		var updatedCp Coupon
		err = couponColl.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&updatedCp)
		if err != nil {
			return map[string]string{"msg": "Coupon invalid, expired, already used, or limit reached"}, 400, nil
		}

		startPoint := now
		if user.ExpiryDate != nil && user.ExpiryDate.After(now) {
			startPoint = *user.ExpiryDate
		}
		newExpiry := startPoint.Add(time.Duration(updatedCp.BonusDays) * 24 * time.Hour)

		_, err = database.Collection("users").UpdateOne(ctx, bson.M{"_id": userOID}, bson.M{
			"$set": bson.M{"expiryDate": newExpiry},
			"$inc": bson.M{"total_purchases": 1},
		})

		if err != nil {
			log.Printf("[ROLLBACK] Coupon %s for user %s failed. Rolling back. err=%v", updatedCp.Code, userIDStr, err)
			_, _ = couponColl.UpdateOne(context.Background(), bson.M{"_id": updatedCp.ID}, bson.M{
				"$inc":  bson.M{"uses": -1},
				"$pull": bson.M{"used_by": userOID},
			})
			return map[string]string{"msg": "Failed to apply coupon, please retry"}, 500, err
		}

		if updatedCp.MaxUses != nil && updatedCp.Uses >= *updatedCp.MaxUses {
			_, _ = couponColl.DeleteOne(context.Background(), bson.M{"_id": updatedCp.ID})
		}

		return map[string]interface{}{
			"msg":        "Coupon applied successfully",
			"new_expiry": newExpiry.Format(time.RFC3339),
		}, 200, nil
	}

	if txHash == "" {
		return map[string]string{"msg": "TX Hash required if no coupon"}, 400, nil
	}

	count, err := database.Collection("transactions").CountDocuments(ctx, bson.M{"tx_hash": txHash})
	if err != nil {
		return nil, 500, err
	}
	if count > 0 {
		return map[string]string{"msg": "Transaction already submitted"}, 409, nil
	}

	newTx := Transaction{
		UserID:    userOID,
		Username:  user.Username,
		TxHash:    txHash,
		Days:      daysReq,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}

	res, err := database.Collection("transactions").InsertOne(ctx, newTx)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return map[string]string{"msg": "Transaction already submitted"}, 409, nil
		}
		return nil, 500, err
	}

	idStr := res.InsertedID.(primitive.ObjectID).Hex()
	return map[string]interface{}{
		"msg":   "Transaction pending approval",
		"tx_id": idStr,
	}, 201, nil
}

// ----- AUTH & MIDDLEWARE -----

type CustomClaims struct {
	SessionSalt string `json:"session_salt"`
	jwt.RegisteredClaims
}

func generateTokens(username, salt string) (string, string, error) {
	if len(cfg.JWTSecret) == 0 {
		return "", "", errors.New("jwt secret not configured")
	}

	accClaims := CustomClaims{
		SessionSalt: salt,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(4 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accClaims)
	accStr, err := token.SignedString(cfg.JWTSecret)
	if err != nil {
		return "", "", err
	}

	refClaims := CustomClaims{
		SessionSalt: salt,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
		},
	}
	rToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refClaims)
	refStr, err := rToken.SignedString(cfg.JWTSecret)
	return accStr, refStr, err
}

func AuthMiddleware(requiredAdmin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, derr := getDB()
		if derr != nil {
			c.AbortWithStatusJSON(500, gin.H{"msg": "Service unavailable"})
			return
		}
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Missing or Invalid Token"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &CustomClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return cfg.JWTSecret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Invalid Token"})
			return
		}

		username := claims.Subject

		database, err := getDB()
		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{"msg": "Service unavailable"})
			return
		}

		var user User
		if err := database.Collection("users").FindOne(context.Background(), bson.M{"username": username}).Decode(&user); err != nil {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Session expired or overridden"})
			return
		}

		if user.SessionSalt != claims.SessionSalt {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Session expired or overridden"})
			return
		}

		isAdmin := user.Role == "admin"
		for _, adm := range cfg.AdminUsernames {
			if adm == username {
				isAdmin = true
				break
			}
		}
		if cfg.AdminEnvUser != "" && username == cfg.AdminEnvUser {
			isAdmin = true
		}

		if requiredAdmin && !isAdmin {
			c.AbortWithStatusJSON(403, gin.H{"msg": "Admin access required"})
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

// ----- HANDLERS -----

func register(c *gin.Context) {
	database, derr := getDB()
	if derr != nil {
		c.JSON(500, gin.H{"msg": "Service unavailable"})
		return
	}

	var body struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"username": []string{"Missing data"}})
		return
	}

	username := strings.ToLower(strings.TrimSpace(body.Username))
	if len(username) < 3 || strings.Contains(username, " ") {
		c.JSON(400, gin.H{"username": []string{"Invalid username format"}})
		return
	}

	var exists User
	if err := database.Collection("users").FindOne(c, bson.M{"username": username}).Decode(&exists); err == nil {
		c.JSON(409, gin.H{"msg": "Username exists"})
		return
	}

	hashed, _ := hashPassword(body.Password)
	salt := strconv.FormatInt(time.Now().UnixNano(), 10)

	role := "user"
	for _, adm := range cfg.AdminUsernames {
		if adm == username {
			role = "admin"
		}
	}
	if cfg.AdminEnvUser == username {
		role = "admin"
	}

	newUser := User{
		Username:    username,
		Password:    hashed,
		Role:        role,
		SessionSalt: salt,
		CreatedAt:   time.Now().UTC(),
	}

	res, err := database.Collection("users").InsertOne(c, newUser)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			c.JSON(409, gin.H{"msg": "Username exists"})
			return
		}
		c.JSON(500, gin.H{"msg": "DB Error"})
		return
	}
	newUser.ID = res.InsertedID.(primitive.ObjectID)

	at, rt, _ := generateTokens(username, salt)
	c.JSON(201, gin.H{"msg": "Registered", "access_token": at, "refresh_token": rt})
}

func login(c *gin.Context) {
	database, derr := getDB()
	if derr != nil {
		c.JSON(500, gin.H{"msg": "Service unavailable"})
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	c.ShouldBindJSON(&body)
	username := strings.ToLower(strings.TrimSpace(body.Username))

	var user User
	err := database.Collection("users").FindOne(c, bson.M{"username": username}).Decode(&user)
	if err != nil || !checkPassword(body.Password, user.Password) {
		c.JSON(401, gin.H{"msg": "Invalid credentials"})
		return
	}

	newSalt := strconv.FormatInt(time.Now().UnixNano(), 10)
	_, _ = database.Collection("users").UpdateOne(c, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"session_salt": newSalt}})

	at, rt, _ := generateTokens(username, newSalt)
	c.JSON(200, gin.H{"access_token": at, "refresh_token": rt})
}

func getMe(c *gin.Context) {
	database, derr := getDB()
	if derr != nil {
		c.JSON(500, gin.H{"msg": "Service unavailable"})
		return
	}

	u, _ := c.Get("user")
	currentUser := u.(User)

	task := func() (interface{}, int, error) {
		var user User
		if err := database.Collection("users").FindOne(context.Background(), bson.M{"_id": currentUser.ID}).Decode(&user); err != nil {
			return nil, 500, err
		}

		now := time.Now().UTC()
		daysLeft := 0
		expIso := ""

		if user.ExpiryDate != nil {
			expIso = user.ExpiryDate.Format(time.RFC3339)
			if user.ExpiryDate.After(now) {
				daysLeft = int(user.ExpiryDate.Sub(now).Hours() / 24)
			}
		}

		resp := gin.H{
			"username":  user.Username,
			"role":      user.Role,
			"days_left": daysLeft,
		}
		if user.ExpiryDate != nil {
			resp["expiry_iso"] = expIso
		} else {
			resp["expiry_iso"] = nil
		}
		return resp, 200, nil
	}

	res, code, err := SubmitJob(0, task, true)
	if err != nil {
		c.JSON(code, gin.H{"msg": "System error"})
		return
	}
	c.JSON(code, res)
}

func submitPayment(c *gin.Context) {
	database, derr := getDB()
	if derr != nil {
		c.JSON(500, gin.H{"msg": "Service unavailable"})
		return
	}

	u, _ := c.Get("user")
	currentUser := u.(User)

	var body struct {
		Days       *int   `json:"days"`
		TxHash     string `json:"tx_hash"`
		CouponCode string `json:"coupon_code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"msg": "Validation failed"})
		return
	}

	if body.CouponCode == "" && body.Days == nil {
		c.JSON(400, gin.H{"msg": "days is required when no coupon is used"})
		return
	}

	days := 0
	if body.Days != nil {
		days = *body.Days
	}

	if body.CouponCode == "" && (days < 1 || days > 3650) {
		c.JSON(400, gin.H{"msg": "Days must be between 1-3650"})
		return
	}

	task := func() (interface{}, int, error) {
		return logicApplyPayment(currentUser.ID.Hex(), body.CouponCode, body.TxHash, days)
	}

	res, code, err := SubmitJob(10, task, true)
	if err != nil {
		if resMap, ok := res.(map[string]string); ok {
			c.JSON(code, resMap)
			return
		}
		c.JSON(code, gin.H{"msg": "Operation failed", "detail": err.Error()})
		return
	}
	c.JSON(code, res)
}

// ----- ADMIN HANDLERS -----

func adminListTx(c *gin.Context) {
	database, derr := getDB()
	if derr != nil {
		c.JSON(500, gin.H{"msg": "Service unavailable"})
		return
	}

	status := c.Query("status")
	filter := bson.M{}
	if status != "" {
		filter["status"] = status
	}

	opts := options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(100)
	cursor, err := database.Collection("transactions").Find(context.Background(), filter, opts)
	if err != nil {
		c.JSON(500, gin.H{"msg": "DB error"})
		return
	}
	defer cursor.Close(context.Background())

	var rawResults []Transaction
	if err := cursor.All(context.Background(), &rawResults); err != nil {
		c.JSON(500, gin.H{"msg": "DB error"})
		return
	}

	output := []gin.H{}
	for _, tx := range rawResults {
		item := gin.H{
			"_id":        tx.ID.Hex(),
			"user_id":    tx.UserID.Hex(),
			"username":   tx.Username,
			"tx_hash":    tx.TxHash,
			"days":       tx.Days,
			"status":     tx.Status,
			"created_at": tx.CreatedAt.Format(time.RFC3339),
		}
		if tx.ProcessedAt != nil {
			item["processed_at"] = tx.ProcessedAt.Format(time.RFC3339)
		}
		if tx.RejectedAt != nil {
			item["rejected_at"] = tx.RejectedAt.Format(time.RFC3339)
		}
		if tx.RejectReason != "" {
			item["reject_reason"] = tx.RejectReason
		}
		output = append(output, item)
	}
	c.JSON(200, output)
}

func adminApproveTx(c *gin.Context) {
	database, derr := getDB()
	if derr != nil {
		c.JSON(500, gin.H{"msg": "Service unavailable"})
		return
	}

	txID := c.Param("tx_id")
	admin := c.MustGet("user").(User)

	task := func() (interface{}, int, error) {
		ctx := context.Background()
		oid, err := primitive.ObjectIDFromHex(txID)
		if err != nil {
			return map[string]string{"msg": "Invalid ID format"}, 400, nil
		}

		var tx Transaction
		if err := database.Collection("transactions").FindOne(ctx, bson.M{"_id": oid, "status": "pending"}).Decode(&tx); err != nil {
			return map[string]string{"msg": "Transaction not found or not pending"}, 404, nil
		}

		var targetUser User
		if err := database.Collection("users").FindOne(ctx, bson.M{"_id": tx.UserID}).Decode(&targetUser); err != nil {
			return map[string]string{"msg": "Linked user missing"}, 404, nil
		}

		now := time.Now().UTC()
		start := now
		if targetUser.ExpiryDate != nil && targetUser.ExpiryDate.After(now) {
			start = *targetUser.ExpiryDate
		}
		newExp := start.Add(time.Duration(tx.Days) * 24 * time.Hour)

		_, err = database.Collection("users").UpdateOne(ctx, bson.M{"_id": targetUser.ID}, bson.M{
			"$set": bson.M{"expiryDate": newExp},
			"$inc": bson.M{"total_purchases": 1},
		})
		if err != nil {
			return nil, 500, err
		}

		_, err = database.Collection("transactions").UpdateOne(ctx, bson.M{"_id": oid}, bson.M{
			"$set": bson.M{
				"status":       "approved",
				"approved_by":  admin.Username,
				"processed_at": now,
			},
		})
		if err != nil {
			return nil, 500, err
		}

		return map[string]string{"msg": "Approved", "new_expiry": newExp.Format(time.RFC3339)}, 200, nil
	}

	res, code, _ := SubmitJob(5, task, true)
	c.JSON(code, res)
}

func adminRejectTx(c *gin.Context) {
	database, derr := getDB()
	if derr != nil {
		c.JSON(500, gin.H{"msg": "Service unavailable"})
		return
	}

	txID := c.Param("tx_id")
	admin := c.MustGet("user").(User)

	var body struct{ Reason string `json:"reason"` }
	c.ShouldBindJSON(&body)
	if body.Reason == "" {
		body.Reason = "No reason provided"
	}

	task := func() (interface{}, int, error) {
		ctx := context.Background()
		oid, err := primitive.ObjectIDFromHex(txID)
		if err != nil {
			return map[string]string{"msg": "Invalid ID format"}, 400, nil
		}

		var tx Transaction
		if err := database.Collection("transactions").FindOne(ctx, bson.M{"_id": oid, "status": "pending"}).Decode(&tx); err != nil {
			return map[string]string{"msg": "Transaction not found or not pending"}, 404, nil
		}

		_, err = database.Collection("transactions").UpdateOne(ctx,
			bson.M{"_id": oid},
			bson.M{"$set": bson.M{
				"status":        "rejected",
				"rejected_by":   admin.Username,
				"rejected_at":   time.Now().UTC(),
				"reject_reason": body.Reason,
			}},
		)

		if err != nil {
			return nil, 500, err
		}
		return map[string]string{"msg": "Transaction rejected successfully"}, 200, nil
	}

	res, code, _ := SubmitJob(5, task, true)
	c.JSON(code, res)
}

func manageCoupons(c *gin.Context) {
	database, derr := getDB()
	if derr != nil {
		c.JSON(500, gin.H{"msg": "Service unavailable"})
		return
	}

	if c.Request.Method == "GET" {
		cursor, err := database.Collection("coupons").Find(context.Background(), bson.M{}, options.Find().SetSort(bson.M{"created_at": -1}))
		if err != nil {
			c.JSON(500, gin.H{"msg": "DB error"})
			return
		}
		defer cursor.Close(context.Background())

		var coupons []Coupon
		if err := cursor.All(context.Background(), &coupons); err != nil {
			c.JSON(500, gin.H{"msg": "DB error"})
			return
		}

		output := []gin.H{}
		for _, cp := range coupons {
			usedByStrs := []string{}
			for _, u := range cp.UsedBy {
				usedByStrs = append(usedByStrs, u.Hex())
			}

			item := gin.H{
				"_id":        cp.ID.Hex(),
				"code":       cp.Code,
				"bonus_days": cp.BonusDays,
				"max_uses":   cp.MaxUses,
				"uses":       cp.Uses,
				"used_by":    usedByStrs,
				"created_at": cp.CreatedAt.Format(time.RFC3339),
			}
			if cp.ExpiresAt != nil {
				item["expires_at"] = cp.ExpiresAt.Format(time.RFC3339)
			} else {
				item["expires_at"] = nil
			}
			output = append(output, item)
		}
		c.JSON(200, output)
		return
	}

	var body struct {
		Code      string     `json:"code" binding:"required"`
		BonusDays int        `json:"bonus_days" binding:"required"`
		MaxUses   *int       `json:"max_uses"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"msg": err.Error()})
		return
	}

	newC := Coupon{
		Code:      body.Code,
		BonusDays: body.BonusDays,
		MaxUses:   body.MaxUses,
		ExpiresAt: body.ExpiresAt,
		Uses:      0,
		UsedBy:    []primitive.ObjectID{},
		CreatedAt: time.Now().UTC(),
	}

	_, err := database.Collection("coupons").InsertOne(context.Background(), newC)
	if mongo.IsDuplicateKeyError(err) {
		c.JSON(409, gin.H{"msg": "Coupon code already exists"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"msg": "DB error"})
		return
	}
	c.JSON(201, gin.H{"msg": "Coupon created"})
}

// ----- STARTUP TASKS & CLEANUP -----

func ensureIndexesAndAdmin() {
	database, err := getDB()
	if err != nil {
		log.Printf("ensureIndexesAndAdmin: db not ready: %v", err)
		return
	}
	ctx := context.Background()

	_, err = database.Collection("users").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("index users.username: %v", err)
	}
	_, err = database.Collection("transactions").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "tx_hash", Value: 1}},
		Options: options.Index().SetUnique(true).SetSparse(true),
	})
	if err != nil {
		log.Printf("index transactions.tx_hash: %v", err)
	}
	_, err = database.Collection("coupons").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "code", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("index coupons.code: %v", err)
	}

	if cfg.AdminEnvUser != "" && cfg.AdminEnvPass != "" {
		hash, _ := hashPassword(cfg.AdminEnvPass)
		userColl := database.Collection("users")
		if err := userColl.FindOne(ctx, bson.M{"username": cfg.AdminEnvUser}).Err(); err == mongo.ErrNoDocuments {
			_, err := userColl.InsertOne(ctx, User{
				Username:    cfg.AdminEnvUser,
				Password:    hash,
				Role:        "admin",
				SessionSalt: "system",
				CreatedAt:   time.Now().UTC(),
			})
			if err != nil {
				log.Printf("bootstrap admin insert failed: %v", err)
			} else {
				log.Println("Bootstrap admin created")
			}
		}
	}
}

func cleanupCouponsTask(stop <-chan struct{}) {
	wg.Add(1)
	defer wg.Done()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("cleanupCouponsTask recovered: %v", r)
		}
	}()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			log.Println("cleanupCouponsTask stopping")
			return
		case <-ticker.C:
			database, err := getDB()
			if err != nil {
				log.Printf("cleanupCouponsTask: db not ready: %v", err)
				continue
			}
			res, err := database.Collection("coupons").DeleteMany(context.Background(), bson.M{
				"expires_at": bson.M{"$lt": time.Now().UTC()},
			})
			if err != nil {
				log.Printf("cleanupCouponsTask delete error: %v", err)
				continue
			}
			if res.DeletedCount > 0 {
				log.Printf("Deleted %d expired coupons", res.DeletedCount)
			}
		}
	}
}

// ----- MAIN -----

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("config error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectDB(ctx); err != nil {
		log.Fatalf("mongo connect failed: %v", err)
	}

	heap.Init(&jobQueue)
	startWorkers(cfg.WorkerCount)

	go ensureIndexesAndAdmin()
	go cleanupCouponsTask(shutdownCh)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	if origins := os.Getenv("FRONTEND_ORIGINS"); origins != "" {
		corsConfig.AllowAllOrigins = false
		parts := []string{}
		for _, s := range strings.Split(origins, ",") {
			if t := strings.TrimSpace(s); t != "" {
				parts = append(parts, t)
			}
		}
		corsConfig.AllowOrigins = parts
	}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	corsConfig.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	r.Use(cors.New(corsConfig))

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"service":        "TwoManga API",
			"mode":           "Worker Queue PRO (Go)",
			"workers_active": cfg.WorkerCount,
			"db":             mongoClient != nil,
		})
	})

	auth := r.Group("/auth")
	{
		auth.POST("/register", register)
		auth.POST("/login", login)
		auth.GET("/me", AuthMiddleware(false), getMe)
	}

	payment := r.Group("/payment")
	payment.Use(AuthMiddleware(false))
	{
		payment.POST("/submit", submitPayment)
	}

	admin := r.Group("/admin")
	admin.Use(AuthMiddleware(true))
	{
		admin.GET("/transactions", adminListTx)
		admin.POST("/transactions/:tx_id/approve", adminApproveTx)
		admin.POST("/transactions/:tx_id/reject", adminRejectTx)
		admin.GET("/coupons", manageCoupons)
		admin.POST("/coupons", manageCoupons)
	}

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	log.Printf("Server running on port %s", cfg.Port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")

	close(shutdownCh)

	ctxShut, cancelShut := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShut()
	if err := srv.Shutdown(ctxShut); err != nil {
		log.Fatalf("Server Shutdown: %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Println("Timeout waiting for goroutines to finish")
	}

	if mongoClient != nil {
		_ = mongoClient.Disconnect(context.Background())
	}

	log.Println("Bye.")
}
