# ----------------------------
# Stage 1: Builder (ساخت فایل اجرایی)
# ----------------------------
# استفاده از نسخه سبک آلپاین برای بیلد سریع‌تر
FROM golang:1.24-alpine AS builder

# نصب ملزومات (گیت برای دانلود ماژول‌ها ضروری است)
RUN apk add --no-cache git

# تنظیم دایرکتوری کاری
WORKDIR /app

# ابتدا فایل‌های مدیریت پکیج را کپی می‌کنیم تا از کش داکر استفاده شود
# این کار باعث می‌شود اگر کد تغییر کرد ولی پکیج‌ها نه، دانلود مجدد انجام نشود
COPY go.mod go.sum ./

# دانلود وابستگی‌ها
RUN go mod download

# کپی کردن سورس کد برنامه به داخل کانتینر
COPY . .

# بیلد کردن برنامه
# CGO_ENABLED=0: برای ساخت باینری استاتیک (بدون وابستگی به کتابخانه‌های C سیستم)
# -ldflags="-s -w": حذف اطلاعات دیباگ برای کاهش حجم فایل نهایی
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o app .

# ----------------------------
# Stage 2: Runner (محیط اجرای نهایی)
# ----------------------------
FROM alpine:latest

# نصب گواهی‌های SSL (برای اتصال به Mongo Atlas ضروری است) و تنظیمات زمانی
RUN apk add --no-cache ca-certificates tzdata

# ساخت یک کاربر معمولی (Non-root) برای امنیت بیشتر
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# کپی فایل اجرایی از مرحله قبل (Builder)
COPY --from=builder /app/app .

# تغییر مالکیت فایل به کاربر امن
RUN chown appuser:appgroup /app/app

# تغییر به کاربر محدود شده
USER appuser

# اکسپوز کردن پورت پیش‌فرض (جهت اطلاع)
# در PaaS پورت واقعی از طریق متغیر محیطی PORT$ تزریق می‌شود و برنامه شما آن را می‌خواند
EXPOSE 10000

# اجرای برنامه
CMD ["./app"]
