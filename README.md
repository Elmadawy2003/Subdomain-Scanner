# Subdomain Scanner - أداة فحص النطاقات الفرعية

أداة مكتوبة بلغة Go لاكتشاف وفحص النطاقات الفرعية والمسارات النشطة.

## المميزات 🚀

- اكتشاف النطاقات الفرعية باستخدام أدوات متعددة
- التحقق من النطاقات النشطة
- اكتشاف المسارات والصفحات
- معالجة وتنظيف النتائج
- حفظ النتائج في ملفات منظمة

## المتطلبات 📋

- نظام تشغيل Linux (مختبر على Kali Linux)
- Go 1.16 أو أحدث
- صلاحيات root لتثبيت الأدوات

## التثبيت 💻

1. تثبيت Go:
```bash
sudo apt-get update
sudo apt-get install golang
```

2. تحميل البرنامج:
```bash
git clone https://github.com/yourusername/subdomain-scanner.git
cd subdomain-scanner
```

3. تشغيل البرنامج:
```bash
sudo go run main.go example.com
```

البرنامج سيقوم تلقائياً بتثبيت الأدوات المطلوبة:
- Subfinder
- Findomain
- Katana
- FFUF

## طريقة العمل ����

البرنامج يعمل في أربع مراحل:

### المرحلة 1️⃣: اكتشاف النطاقات الفرعية
- استخدام Subfinder
- استخدام Findomain
- حفظ النتائج في `all_subdomains.txt`

### المرحلة 2️⃣: التحقق من النطاقات النشطة
- فحص DNS
- فحص HTTP/HTTPS
- حفظ النتائج في `active_subdomains.txt`

### المرحلة 3️⃣: فحص النطاقات النشطة
- استخدام Katana لاكتشاف الروابط
- استخدام FFUF لاكتشاف المسارات
- حفظ النتائج في ملفات منفصلة لكل نطاق

### المرحلة 4️⃣: معالجة وتنظيف النتائج
- إزالة المكرر
- فلترة النتائج
- التحقق من نشاط الروابط
- حفظ النتائج النهائية في `final_active_urls.txt`

## المخرجات 📁

البرنامج ينشئ المجلدات والملفات التالية:

```
results_domain.com/
├── all_subdomains.txt       # جميع النطاقات الفرعية
├── active_subdomains.txt    # النطاقات النشطة
├── subdomain_all_results.txt # نتائج كل أداة لكل نطاق
└── final_active_urls.txt    # الروابط النشطة النهائية
```

## الخيارات ا��متقدمة ⚙️

### تغيير قائمة كلمات FFUF
البرنامج يستخدم قائمة الكلمات الافتراضية في:
```
/usr/share/wordlists/dirb/common.txt
```

يمكنك استخدام قوائم أخرى مثل:
- `/usr/share/wordlists/dirb/big.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

## الأمان 🔒

- البرنامج يستخدم HTTPS للاتصالات الآمنة
- يتجاهل شهادات SSL غير الصالحة
- يستخدم User-Agent واقعي
- يحترم سياسات الخادم في التأخير والتوقف

## المساهمة 🤝

نرحب بمساهماتكم! يمكنكم:
1. عمل Fork للمشروع
2. إنشاء فرع جديد (`git checkout -b feature/amazing-feature`)
3. عمل Commit للتغييرات (`git commit -m 'Add amazing feature'`)
4. رفع التغييرات (`git push origin feature/amazing-feature`)
5. فتح Pull Request

## الرخصة 📝

هذا المشروع مرخص تحت رخصة MIT - انظر ملف [LICENSE](LICENSE) للتفاصيل.

## الإقرارات 🙏

شكر خاص للأدوات المستخدمة:
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Findomain](https://github.com/Findomain/Findomain)
- [Katana](https://github.com/projectdiscovery/katana)
- [FFUF](https://github.com/ffuf/ffuf)

## التواصل 📧

- اسمك
- البريد الإلكتروني
- Twitter/X
- GitHub 