# سیستم مدیریت کاربر

یک سیستم مدیریت کاربر مبتنی بر Flask با قابلیت‌های ثبت‌نام، ورود، بازنشانی رمز عبور، مدیریت پروفایل و کنترل دسترسی مبتنی بر نقش (کاربر/ادمین). این سیستم از SQLite برای ذخیره داده‌ها، JWT برای احراز هویت و رابط کاربری ساده HTML استفاده می‌کند.

## قابلیت‌ها

- **ثبت‌نام کاربر**: ایجاد حساب با نام کاربری، ایمیل و رمز عبور (با اعتبارسنجی).
- **ورود کاربر**: احراز هویت کاربران و صدور توکن JWT.
- **بازنشانی رمز عبور**: درخواست لینک بازنشانی از طریق ایمیل (در محیط توسعه شبیه‌سازی شده).
- **مدیریت پروفایل**: به‌روزرسانی نام کاربری/ایمیل یا حذف حساب.
- **کنترل دسترسی مبتنی بر نقش**: ادمین‌ها می‌توانند لیست کاربران را مشاهده کرده و کاربران را به نقش ادمین ارتقا دهند.
- **امنیت**: هش رمز عبور (pbkdf2:sha256)، محدودیت نرخ درخواست (`flask-limiter`)، محافظت در برابر CSRF (`flask-wtf`).
- **لاگ‌گیری**: ثبت اقدامات کاربر (ثبت‌نام، ورود، خطاها) در فایل `app.log`.
- **رابط کاربری**: قالب‌های HTML ساده برای ثبت‌نام، ورود و بازنشانی رمز عبور.

## پیش‌نیازها

- پایتون نسخه 3.8 یا بالاتر
- ابزار pip (مدیر بسته‌های پایتون)
- Git (اختیاری، برای کنترل نسخه)

## نصب

1. **دریافت پروژه** (در صورت استفاده از Git):

   ```bash
   git clone <آدرس-مخزن-شما>
   cd user_management_project
   ```

   یا یک دایرکتوری جدید ایجاد کرده و فایل‌های پروژه را در آن کپی کنید.

2. **ایجاد ساختار پروژه**: ساختار دایرکتوری باید به این صورت باشد:

   ```
   user_management_project/
   ├── user_management.py
   ├── templates/
   │   ├── index.html
   │   ├── register.html
   │   ├── login.html
   │   ├── reset_password_request.html
   │   ├── reset_password.html
   ├── requirements.txt
   └── app.log
   ```

3. **نصب وابستگی‌ها**: یک محیط مجازی (توصیه‌شده) ایجاد کنید:

   ```bash
   python -m venv venv
   source venv/bin/activate  # در ویندوز: venv\Scripts\activate
   ```

   بسته‌های موردنیاز را نصب کنید:

   ```bash
   pip install -r requirements.txt
   ```

   محتوای فایل `requirements.txt`:

   ```
   flask==2.3.2
   flask-sqlalchemy==3.0.5
   flask-limiter==3.5.0
   flask-wtf==1.1.1
   werkzeug==2.3.6
   pyjwt==2.8.0
   ```

## راه‌اندازی

1. **تنظیم متغیرهای محیطی**: یک `SECRET_KEY` امن برای Flask و JWT تنظیم کنید:

   ```bash
   export FLASK_SECRET_KEY='کلید-امن-شما'  # در ویندوز: set FLASK_SECRET_KEY=کلید-امن-شما
   ```

   یا در فایل `user_management.py` از `os.getenv` استفاده کنید:

   ```python
   import os
   app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
   ```

2. **راه‌اندازی پایگاه داده**: پایگاه داده SQLite (`users.db`) به‌صورت خودکار هنگام اولین اجرای برنامه ایجاد می‌شود.

3. **اجرای برنامه**:

   ```bash
   python user_management.py
   ```

   برنامه روی `http://localhost:5000` اجرا می‌شود.

## استفاده

### رابط کاربری وب

- **صفحه اصلی**: به `http://localhost:5000/` بروید برای دسترسی به لینک‌های ثبت‌نام، ورود یا درخواست بازنشانی رمز.
- **ثبت‌نام**: به `http://localhost:5000/register` بروید برای ایجاد حساب جدید.
- **ورود**: به `http://localhost:5000/login` بروید برای ورود.
- **درخواست بازنشانی رمز**: به `http://localhost:5000/reset-password-request` بروید برای درخواست لینک بازنشانی.
- **بازنشانی رمز**: با استفاده از توکن دریافتی به `http://localhost:5000/reset-password/<token>` بروید.

### APIها

از ابزارهایی مثل Postman یا cURL برای تعامل با APIها استفاده کنید:

- **ثبت‌نام**: `POST /api/register`

  ```json
  {
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test1234"
  }
  ```
- **ورود**: `POST /api/login`

  ```json
  {
    "username": "testuser",
    "password": "Test1234"
  }
  ```

  توکن JWT را برمی‌گرداند.
- **درخواست بازنشانی رمز**: `POST /api/reset-password-request`

  ```json
  {
    "email": "test@example.com"
  }
  ```
- **بازنشانی رمز**: `POST /api/reset-password/<token>`

  ```json
  {
    "password": "NewPass1234"
  }
  ```
- **مشاهده پروفایل**: `GET /api/profile` (نیاز به هدر `Authorization: <token>`)
- **به‌روزرسانی پروفایل**: `PUT /api/profile` (نیاز به هدر `Authorization: <token>`)

  ```json
  {
    "username": "newuser",
    "email": "new@example.com"
  }
  ```
- **حذف حساب**: `DELETE /api/profile` (نیاز به هدر `Authorization: <token>`)
- **لیست کاربران (ادمین)**: `GET /api/admin/users` (نیاز به هدر `Authorization: <token>` و نقش ادمین)
- **ارتقای کاربر به ادمین**: `PUT /api/admin/users/<user_id>/promote` (نیاز به هدر `Authorization: <token>` و نقش ادمین)

## ایجاد کاربر ادمین

برای تست مسیرهای ادمین، نقش یک کاربر را در پایگاه داده به `admin` تغییر دهید:

```bash
sqlite3 users.db
UPDATE user SET role = 'admin' WHERE username = 'testuser';
```

## نکات امنیتی

- **کلید مخفی**: در محیط تولید، `SECRET_KEY` را در متغیر محیطی ذخیره کنید و از مقدار ثابت در کد اجتناب کنید.
- **ایمیل واقعی**: در محیط توسعه، ایمیل‌ها در کنسول چاپ می‌شوند. برای ارسال ایمیل واقعی، تابع `send_reset_email` را با SMTP (مثل Gmail) تنظیم کنید:

  ```python
  import smtplib
  from email.mime.text import MIMEText
  
  def send_reset_email(email, token):
      msg = MIMEText(f'Reset your password: http://yourdomain.com/reset-password/{token}')
      msg['Subject'] = 'Password Reset Request'
      msg['From'] = 'no-reply@yourapp.com'
      msg['To'] = email
      with smtplib.SMTP('smtp.gmail.com', 587) as server:
          server.starttls()
          server.login('your-email@gmail.com', 'your-app-password')
          server.sendmail(msg['From'], msg['To'], msg.as_string())
  ```

  برای Gmail، باید "App Password" ایجاد کنید.
- **HTTPS**: در تولید، برنامه را با HTTPS اجرا کنید.
- **پایگاه داده**: برای تولید، از پایگاه داده قوی‌تر مثل PostgreSQL استفاده کنید.

## عیب‌یابی

- **خطای نصب وابستگی‌ها**: مطمئن شوید از Python 3.8+ استفاده می‌کنید و نسخه‌های بسته‌ها با `requirements.txt` مطابقت دارند.
- **خطای CSRF**: بررسی کنید که `csrf_token()` در فرم‌های HTML به‌درستی استفاده شده باشد.
- **لاگ‌ها**: فایل `app.log` را برای شناسایی خطاها بررسی کنید.
- **محدودیت‌های Pyodide**: در محیط‌های محدود مثل Pyodide، ارسال ایمیل واقعی یا استفاده از Redis برای `flask-limiter` ممکن نیست.

## ذخیره پروژه در Git

1. مخزن Git را ایجاد کنید:

   ```bash
   git init
   echo "users.db" > .gitignore
   echo "app.log" >> .gitignore
   git add .
   git commit -m "Initial commit"
   ```
2. پروژه را به GitHub آپلود کنید:

   ```bash
   git remote add origin <آدرس-مخزن-شما>
   git push -u origin main
   ```

## توسعه بیشتر

برای افزودن قابلیت‌های بیشتر، می‌توانید موارد زیر را پیاده‌سازی کنید:

- احراز هویت دو مرحله‌ای (2FA)
- ادغام با سرویس‌های ایمیل واقعی (مثل SendGrid)
- افزودن تست‌های واحد (Unit Tests) با pytest
- استقرار پروژه روی سرور (مثل Heroku یا AWS)

## تماس

برای سؤالات یا پیشنهادات، با توسعه‌دهنده پروژه تماس بگیرید: \[erfankhanamani@gmail.com\]