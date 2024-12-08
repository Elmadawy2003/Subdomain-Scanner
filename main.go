package main

import (
	"crypto/tls"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	ActiveSubdomains []string                     `json:"active_subdomains"`
	URLs            map[string]string             `json:"urls"`
	Parameters      map[string][]string           `json:"parameters"`
	Pages           map[string]map[string]string  `json:"pages"`
}

func checkAndInstallTools() error {
	fmt.Println("[*] جاري التحقق من وجود الأدوات المطلوبة...")
	
	// التحقق من وجود Go
	if _, err := exec.LookPath("go"); err != nil {
		fmt.Println("[!] Go غير مثبت. يرجى تنفيذ:")
		fmt.Println("sudo apt-get install golang")
		return fmt.Errorf("Go غير مثبت")
	}

	tools := map[string]struct {
		checkCmd    string
		installCmd  string
		installType string
	}{
		"subfinder": {
			checkCmd:    "which subfinder",
			installCmd:  "GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			installType: "go",
		},
		"findomain": {
			checkCmd:    "which findomain",
			installCmd:  "sudo apt-get install -y findomain",
			installType: "apt",
		},
		"katana": {
			checkCmd:    "which katana",
			installCmd:  "GO111MODULE=on go install github.com/projectdiscovery/katana/cmd/katana@latest",
			installType: "go",
		},
		"ffuf": {
			checkCmd:    "which ffuf",
			installCmd:  "GO111MODULE=on go install github.com/ffuf/ffuf@latest",
			installType: "go",
		},
	}

	for toolName, tool := range tools {
		fmt.Printf("[*] التحقق من وجود %s...\n", toolName)
		cmd := exec.Command("bash", "-c", tool.checkCmd)
		if err := cmd.Run(); err != nil {
			fmt.Printf("[!] %s غير موجود. جاري التثبيت...\n", toolName)
			var installCmd *exec.Cmd
			
			switch tool.installType {
			case "go":
				installCmd = exec.Command("bash", "-c", tool.installCmd)
				// إضافة مسار Go bin إلى PATH
				os.Setenv("PATH", os.Getenv("PATH")+":"+os.Getenv("HOME")+"/go/bin")
			case "apt":
				installCmd = exec.Command("bash", "-c", tool.installCmd)
			case "pip":
				installCmd = exec.Command("pip3", "install", toolName)
			}
			
			output, err := installCmd.CombinedOutput()
			if err != nil {
				fmt.Printf("[!] فشل في تثبيت %s: %v\n%s\n", toolName, err, string(output))
				return err
			}
			fmt.Printf("[+] تم تثبيت %s بنجاح\n", toolName)
		} else {
			fmt.Printf("[+] %s موجود\n", toolName)
		}
	}

	fmt.Println("[+] تم التحقق من جميع الأدوات بنجاح")
	return nil
}

func runSubfinder(domain string) []string {
	fmt.Printf("[*] جاري تشغيل Subfinder على %s\n", domain)
	cmd := exec.Command("subfinder", "-d", domain, "-silent")
	
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[!] خطأ في تنفيذ Subfinder: %v\n", err)
		return nil
	}
	
	subdomains := strings.Split(string(output), "\n")
	if len(subdomains) > 0 {
		fmt.Printf("[+] Subfinder: تم العثور على %d نطاق\n", len(subdomains))
	}
	return subdomains
}

func runFindomain(domain string) []string {
	fmt.Printf("[*] جاري تشغيل Findomain على %s\n", domain)
	cmd := exec.Command("findomain", "-t", domain, "--quiet")
	
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[!] خطأ في تنفيذ Findomain: %v\n", err)
		return nil
	}
	
	subdomains := strings.Split(string(output), "\n")
	if len(subdomains) > 0 {
		fmt.Printf("[+] Findomain: تم العثور على %d نطاق\n", len(subdomains))
	}
	return subdomains
}

func runKatana(url string) []string {
	fmt.Printf("[*] جاري تشغيل Katana على %s\n", url)
	cmd := exec.Command("katana", "-u", url, "-silent")
	
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[!] خطأ في تنفيذ Katana: %v\n", err)
		return nil
	}
	
	urls := strings.Split(string(output), "\n")
	if len(urls) > 0 {
		fmt.Printf("[+] Katana: تم العثور على %d رابط\n", len(urls))
	}
	return urls
}

func runFFUF(url string) []string {
	fmt.Printf("[*] جاري تشغيل FFUF على %s\n", url)
	
	// المسار الافتراضي لقوائم الكلمات في Kali Linux
	wordlistPath := "/usr/share/wordlists/dirb/common.txt"
	
	// التحقق من وجود ملف القائمة
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		fmt.Printf("[!] قائمة الكلمات غير موجودة في %s\n", wordlistPath)
		fmt.Println("[*] جاري تحميل قائمة الكلمات...")
		
		// إنشاء المجلد إذا لم يكن موجوداً
		if err := os.MkdirAll("/usr/share/wordlists/dirb", 0755); err != nil {
			fmt.Printf("[!] خطأ في إنشاء المجلد: %v\n", err)
			return nil
		}
		
		// تحميل قائمة الكلمات
		cmd := exec.Command("wget", 
			"https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt",
			"-O", wordlistPath)
		
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("[!] خطأ في تحميل قائمة الكلمات: %v\n%s\n", err, string(output))
			return nil
		}
	}
	
	// إنشاء مجلد مؤقت للنتائج
	tempDir := "ffuf_output"
	os.MkdirAll(tempDir, 0755)
	outputFile := "ffuf_results.json"
	
	// تشغيل FFUF
	cmd := exec.Command("ffuf",
		"-u", url+"/FUZZ",
		"-w", wordlistPath,
		"-mc", "200,201,202,203,204,301,302,307,401,403,405",
		"-o", outputFile,
		"-of", "json",
		"-c",
		"-t", "50")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[!] خطأ في تنفيذ FFUF: %v\n%s\n", err, string(output))
		return nil
	}
	
	// قراءة نتائج FFUF
	content, err := os.ReadFile(outputFile)
	if err != nil {
		fmt.Printf("[!] خطأ في قراءة نتائج FFUF: %v\n", err)
		return nil
	}
	
	// تحليل نتائج JSON
	var ffufResults struct {
		Results []struct {
			URL string `json:"url"`
		} `json:"results"`
	}
	
	if err := json.Unmarshal(content, &ffufResults); err != nil {
		fmt.Printf("[!] خطأ في تحليل نتائج FFUF: %v\n", err)
		return nil
	}
	
	// تجميع URLs
	var results []string
	for _, result := range ffufResults.Results {
		results = append(results, result.URL)
	}
	
	// تنظيف
	os.Remove(outputFile)
	
	if len(results) > 0 {
		fmt.Printf("[+] FFUF: تم العثور على %d مسار\n", len(results))
	}
	
	return results
}

func isSubdomainActive(subdomain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	if subdomain == "" {
		return
	}

	fmt.Printf("[*] جاري فحص النطاق: %s\n", subdomain)

	// فحص DNS أولاً مع timeout
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dnsCancel()
	
	var resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	
	_, err := resolver.LookupHost(dnsCtx, subdomain)
	if err != nil {
		return
	}

	// فحص HTTP/HTTPS بشكل متوازي
	var httpWg sync.WaitGroup
	isActive := make(chan bool, 1)
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     5 * time.Second,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 10,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range []string{"https://", "http://"} {
		httpWg.Add(1)
		go func(url string) {
			defer httpWg.Done()
			
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
			
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			
			select {
			case isActive <- true:
				fmt.Printf("[+] النطاق نشط: %s [%d]\n", url, resp.StatusCode)
			default:
			}
		}(scheme + subdomain)
	}

	// انتظار انتهاء جميع الفحوصات أو timeout
	done := make(chan bool)
	go func() {
		httpWg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		return
	}

	// إذا كان النطاق نشط، أرسله إلى القناة
	select {
	case <-isActive:
		results <- subdomain
	default:
	}
}

func cleanDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	
	return strings.TrimSpace(domain)
}

func cleanURL(url string) string {
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, "#"); idx != -1 {
		url = url[:idx]
	}
	return strings.TrimSpace(url)
}

func saveToFile(filename string, content []string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("خطأ في إنشاء الملف %s: %v", filename, err)
	}
	defer f.Close()

	seen := make(map[string]bool)
	for _, line := range content {
		if line = strings.TrimSpace(line); line != "" {
			if filename == "phase1_active_subdomains.txt" {
				line = cleanDomain(line)
			} else {
				line = cleanURL(line)
			}
			if !seen[line] {
				_, err := f.WriteString(line + "\n")
				if err != nil {
					return fmt.Errorf("خطأ في الكتابة إلى الملف %s: %v", filename, err)
				}
				seen[line] = true
			}
		}
	}
	
	fmt.Printf("[+] تم حفظ النتائج في الملف: %s\n", filename)
	return nil
}

func crawlPages(url string) map[string]string {
	pages := make(map[string]string)
	
	// تشغيل Katana
	katanaResults := runKatana(url)
	for _, result := range katanaResults {
		if result != "" {
			pages[result] = "katana"
		}
	}
	
	// تشغيل FFUF
	ffufResults := runFFUF(url)
	for _, result := range ffufResults {
		if result != "" {
			pages[result] = "ffuf"
		}
	}
	
	return pages
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, item := range slice {
		if item = strings.TrimSpace(item); item != "" {
			if !seen[item] {
				seen[item] = true
				result = append(result, item)
			}
		}
	}
	
	return result
}

func saveToolResults(subdomain string, toolName string, results []string) error {
	// إنشاء ملف واحد لكل subdomain يحتوي على نتائج جميع الأدوات
	filename := fmt.Sprintf("%s_all_results.txt", subdomain)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("خطأ في فتح الملف %s: %v", filename, err)
	}
	defer f.Close()

	// كتابة اسم الأداة كعنوان
	if _, err := f.WriteString(fmt.Sprintf("\n\n=== نتائج %s ===\n", toolName)); err != nil {
		return fmt.Errorf("خطأ في كتابة العنوان: %v", err)
	}

	// كتابة النتائج
	for _, result := range results {
		if result = strings.TrimSpace(result); result != "" {
			if _, err := f.WriteString(result + "\n"); err != nil {
				return fmt.Errorf("خطأ في كتابة النتائج: %v", err)
			}
		}
	}

	fmt.Printf("[+] تم إضافة نتائج %s إلى الملف: %s\n", toolName, filename)
	return nil
}

func processSubdomain(subdomain string, results chan<- map[string]interface{}, wg *sync.WaitGroup) {
	defer wg.Done()
	
	fmt.Printf("\n[*] جاري معالجة النطاق: %s\n", subdomain)
	subdomainResults := make(map[string]interface{})
	subdomainResults["subdomain"] = subdomain
	
	// 1. تشغيل Katana
	fmt.Printf("[*] تشغيل Katana على %s\n", subdomain)
	katanaResults := runKatana("http://" + subdomain)
	if len(katanaResults) > 0 {
		subdomainResults["katana"] = katanaResults
		saveToolResults(subdomain, "katana", katanaResults)
	}
	
	// 2. تشغيل FFUF
	fmt.Printf("[*] تشغيل FFUF على %s\n", subdomain)
	ffufResults := runFFUF("http://" + subdomain)
	if len(ffufResults) > 0 {
		subdomainResults["ffuf"] = ffufResults
		saveToolResults(subdomain, "ffuf", ffufResults)
	}
	
	results <- subdomainResults
}

func cleanAndFilterURLs(urls []string) []string {
	// إزالة المكرر وتنظيف URLs
	seen := make(map[string]bool)
	var cleaned []string
	
	for _, url := range urls {
		// تنظيف URL
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		
		// تجاهل الملفات الثابتة والموارد
		if strings.HasSuffix(url, ".css") ||
			strings.HasSuffix(url, ".js") ||
			strings.HasSuffix(url, ".jpg") ||
			strings.HasSuffix(url, ".jpeg") ||
			strings.HasSuffix(url, ".png") ||
			strings.HasSuffix(url, ".gif") ||
			strings.HasSuffix(url, ".svg") ||
			strings.HasSuffix(url, ".woff") ||
			strings.HasSuffix(url, ".woff2") ||
			strings.HasSuffix(url, ".ttf") ||
			strings.HasSuffix(url, ".eot") {
			continue
		}
		
		if !seen[url] {
			seen[url] = true
			cleaned = append(cleaned, url)
		}
	}
	
	return cleaned
}

func checkURLActive(url string) bool {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// اعتبار الصفحة نشطة إذا كان الرد 2xx أو 3xx
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func processAndFilterResults(toolResults []map[string]interface{}) {
	fmt.Println("\n[+] المرحلة 4: معالجة وتنظيف النتائج...")
	
	var allURLs []string
	
	// جمع كل URLs من جميع الأدوات
	for _, result := range toolResults {
		if katanaResults, ok := result["katana"].([]string); ok {
			allURLs = append(allURLs, katanaResults...)
		}
		if ffufResults, ok := result["ffuf"].([]string); ok {
			allURLs = append(allURLs, ffufResults...)
		}
	}
	
	// تنظيف وإزالة المكرر
	cleanedURLs := cleanAndFilterURLs(allURLs)
	fmt.Printf("[+] تم العثور على %d رابط فريد بعد التنظيف\n", len(cleanedURLs))
	
	// التحقق من النشاط
	var activeURLs []string
	var wg sync.WaitGroup
	results := make(chan string, len(cleanedURLs))
	semaphore := make(chan struct{}, 20) // 20 عملية متو��زية
	
	for _, url := range cleanedURLs {
		wg.Add(1)
		semaphore <- struct{}{}
		
		go func(u string) {
			defer func() {
				<-semaphore
				wg.Done()
			}()
			
			if checkURLActive(u) {
				results <- u
				fmt.Printf("[+] رابط نشط: %s\n", u)
			}
		}(url)
	}
	
	go func() {
		wg.Wait()
		close(results)
	}()
	
	for url := range results {
		activeURLs = append(activeURLs, url)
	}
	
	// حفظ النتائج النهائية
	if err := saveToFile("final_active_urls.txt", activeURLs); err != nil {
		fmt.Printf("[!] خطأ في حفظ الروابط النشطة: %v\n", err)
	}
	
	fmt.Printf("\n[+] النتائج النهائية:")
	fmt.Printf("\n    - إجمالي الروابط: %d", len(allURLs))
	fmt.Printf("\n    - الروابط الفريدة بعد التنظيف: %d", len(cleanedURLs))
	fmt.Printf("\n    - الروابط النشطة: %d\n", len(activeURLs))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("الاستخدام: go run main.go example.com")
		os.Exit(1)
	}

	// التحقق من وجود الأدوات وتثبيتها
	if err := checkAndInstallTools(); err != nil {
		fmt.Printf("[!] فشل في التحقق من الأدوات: %v\n", err)
		os.Exit(1)
	}

	domain := os.Args[1]
	fmt.Printf("\n[+] بدء الفحص على النطاق: %s\n", domain)

	// المرحلة 1: اكتشاف النطاقات الفرعية
	fmt.Println("\n[+] المرحلة 1: اكتشاف النطاقات الفرعية...")
	
	var allSubdomains []string
	
	// تشغيل Subfinder
	if subs := runSubfinder(domain); subs != nil {
		allSubdomains = append(allSubdomains, subs...)
	}
	
	// تشغيل Findomain
	if subs := runFindomain(domain); subs != nil {
		allSubdomains = append(allSubdomains, subs...)
	}
	
	// إزالة التكرار
	allSubdomains = removeDuplicates(allSubdomains)
	
	// حفظ جميع النطاقات الفرعية
	if err := saveToFile("all_subdomains.txt", allSubdomains); err != nil {
		fmt.Printf("[!] خطأ في حفظ النطاقات الفرعية: %v\n", err)
	}
	
	fmt.Printf("[+] تم العثور على %d نطاق فرعي\n", len(allSubdomains))
	
	// المرحلة 2: التحقق من النطاقات النشطة
	fmt.Println("\n[+] المرحلة 2: التحقق من النطاقات النشطة...")
	
	activeResults := make(chan string, len(allSubdomains))
	var activeWg sync.WaitGroup
	
	// تحديد عدد العمليات المتوازية (50 عملية في نفس الوقت)
	semaphore := make(chan struct{}, 50)
	
	for _, subdomain := range allSubdomains {
		activeWg.Add(1)
		semaphore <- struct{}{} // حجز مكان في السيمافور
		
		go func(sub string) {
			defer func() { <-semaphore }() // تحرير مكان في السيمافور عند الانتهاء
			isSubdomainActive(sub, activeResults, &activeWg)
		}(subdomain)
	}
	
	// إغلاق قناة النتائج بعد انتهاء جميع العمليات
	go func() {
		activeWg.Wait()
		close(activeResults)
	}()
	
	// تجميع النطاقات النشطة
	var activeSubdomains []string
	for subdomain := range activeResults {
		activeSubdomains = append(activeSubdomains, subdomain)
	}
	
	// حفظ النطاقات النشطة
	if err := saveToFile("active_subdomains.txt", activeSubdomains); err != nil {
		fmt.Printf("[!] خطأ في حفظ النطاقات النشطة: %v\n", err)
	}
	
	fmt.Printf("[+] تم العثور على %d نطاق نشط\n", len(activeSubdomains))
	
	// المرحلة 3: فحص كل نطاق نشط باستخدام جميع الأدوات
	fmt.Println("\n[+] المرحلة 3: فحص النطاقات النشطة...")
	
	// إنشاء مجلد للنتائج
	resultsDir := "results_" + domain
	os.MkdirAll(resultsDir, 0755)
	os.Chdir(resultsDir)
	
	toolResults := make(chan map[string]interface{}, len(activeSubdomains))
	var toolsWg sync.WaitGroup
	
	for _, subdomain := range activeSubdomains {
		toolsWg.Add(1)
		go processSubdomain(subdomain, toolResults, &toolsWg)
	}
	
	// إغلاق قناة النتائج بعد انتهاء جميع العمليات
	go func() {
		toolsWg.Wait()
		close(toolResults)
	}()
	
	// تجميع النتائج
	var allResults []map[string]interface{}
	for result := range toolResults {
		allResults = append(allResults, result)
	}
	
	// معالجة وتنظيف النتائج
	processAndFilterResults(allResults)
	
	// حفظ جميع النتائج في ملف JSON
	jsonData, err := json.MarshalIndent(allResults, "", "    ")
	if err != nil {
		fmt.Printf("[!] خطأ في تحويل النتائج إلى JSON: %v\n", err)
	} else {
		if err := os.WriteFile("all_results.json", jsonData, 0644); err != nil {
			fmt.Printf("[!] خطأ في حفظ النتائج: %v\n", err)
		}
	}
	
	fmt.Println("\n[+] تم الانتهاء من الفحص!")
	fmt.Printf("[+] يمكنك العثور على جميع النتائج في المجلد: %s\n", resultsDir)
} 