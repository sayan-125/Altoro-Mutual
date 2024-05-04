# Altoro Mutual Website Report

## **Website URL: http://testfire.net**

![Capture](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/95e4afd0-b0fc-4d75-8f4e-fc1d3b4be514)


## **Vulnerability 01**

**Vulnerability Title:** Reflected XSS

**Severity:** Medium

**Vulnerable URL:** http://testfire.net/search.jsp?query=%3Cimg+src%2Fonerror%3Dprompt%2850%29%3E

**Description:** Reflected XSS attacks, also known as non-persistent attacks, occur when a malicious script is reflected off of a web application to the victim’s browser.

**PoC (Proof of Concept):**

	Step1: Goto http://testfire.net/
	
	Step2: Search column inject <img/src/onerror=prompt(50)>
	
	Step3: The message box is displaying

**Snapshots/Screenshot:**

![ss-1](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/0b668872-6009-41e2-91cb-28699a0dc595)

**Recommendation/Mitigation/Remediation:**

	Validate user input
	
	Implement Content security policy


## **Vulnerability 02**

**Vulnerability Title:** Login Page Bypass using SQL Injection

**Severity:** Critical

**Vulnerable URL:** http://testfire.net/login.jsp

**Description:** SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.

**PoC (Proof of Concept):**
	
	Step1: Go to http://testfire.net/login.jsp
	
	Step2: Enter username as ‘ or 1=1-- - and password random some keys
	
	Step3: Click on login and we login as administrator

**Snapshots/Screenshot:**

![ss-2](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/1ae01c22-017d-4354-a0db-6dc5d1413d67)

**Recommendation/Mitigation/Remediation:**

	Filter User Input
	
	Sanitize User Input / Prepared Statements


## **Vulnerability 03**

Vulnerability Title: Cross-Site Scripting (Reflected)

**Severity:** Critical

**Vulnerable URL:** http://testfire.net/feedback.jsp

**Description:** Reflected XSS is a kind of cross-site scripting attack, where malicious script is injected into websites that are trusted or otherwise benign. Typically, the injection occurs when an unsuspecting user clicks on a link that is specifically designed to attack the website they are visiting.

**PoC (Proof of Concept):**

	Step1: Go to http://testfire.net/feedback.jsp
	
	Step2: Enter Your Name as </p><scrIpt>alert(1);</scRipt><p>
	
	Step3: Click on submit

**Snapshots/Screenshot:**

![ss-5](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/bdec6205-acf5-4dc6-a95a-d49372e93bb2)

![ss-4](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/1e595577-bb10-4c5a-b263-61b36924f309)

**Recommendation/Mitigation/Remediation:**

	Validate user input
	
	Implement Content security policy


## **Vulnerability 04**

**Vulnerability Title:** URL Redirection Attack

**Severity:** Medium

**Vulnerable URL:** http://testfire.net/bank/customize.jsp

**Description:** URL Redirection is a vulnerability which allows an attacker to force users of your application to an untrusted external site. The attack is most often performed by delivering a link to the victim, who then clicks the link and is unknowingly redirected to the malicious website.

**PoC (Proof of Concept):**

	Step1: Go to http://testfire.net/bank/customize.jsp
	
	Step2: Then add in url ?content=https://www.google.com&lang=international%20HTTP/1.1 HTTP/1.1
	
	Step3: Then press enter

**Snapshots/Screenshot:**

![ss-6](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/789c00b4-d134-4726-a31a-4768ee02e7b7)

![ss-7](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/5d26d8ed-29b0-4d01-8611-06cf81c102a0)

**Recommendation/Mitigation/Remediation:**

	Validate and Sanitize Input
	
	Use Whitelists for Allowed Redirect Targets


## **Vulnerability 05**

**Vulnerability Title:** ClickJacking

**Severity:** Medium

**Vulnerable URL:** http://testfire.net/index.jsp

**Description:** Clickjacking is an attack that tricks a user into clicking a webpage element which is invisible or disguised as another element. This can cause users to unwittingly download malware, visit malicious web pages, provide credentials or sensitive information, transfer money, or purchase products online.

**PoC (Proof of Concept):**

	Step1: Go to http://testfire.net/index.jsp
	
	Step2: Then open Burp Suite and connect and then capture code
	
	Step3: Then create an HTML file. Write this code:
	
	<html>
	<head>
	<title>Clickjack test page</title>
	</head>
	<body>
	<p>Website is vulnerable to clickjacking</p>
	<iframe src="http://testfire.net/" width="500"height="500"></iframe>
	</body>
	</html>
	
	Step 4: Run this HTML file

**Snapshots/Screenshot:**

![ss-11](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/34da3bd0-9dea-4a22-98d8-66d8ad7dc00e)

**Recommendation/Mitigation/Remediation:**

	Frame Busting Code
	
	X-Frame-Options Header


## **Vulnerability 06**

**Vulnerability Title:** Link Injection

**Severity:** Medium

**Vulnerable URL:** http://testfire.net/index.jsp

**Description:** Link Injection vulnerability arises when the attacker’s injected hyperlink gets successfully sent in the emails. Majority of the times, this attack involves user interaction.

**PoC (Proof of Concept):**

	Step1: Go to http://testfire.net/index.jsp
	
	Step2: Then add in url ?content=”’><A HREF=”/WF_XSRF252.html”>InjectedLink</A>HTTP/1.1
	
	Step3: Then press enter

**Snapshots/Screenshot:**

![ss-8](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/cdfcbd7c-8c18-499a-a51b-db96003bd08a)

**Recommendation/Mitigation/Remediation:**

	Input Validation and Sanitization
	
	Encode Output


## **Vulnerability 07**

**Vulnerability Title:** Server Leaks Version Information

**Severity:** Low

**Vulnerable URL:** http://testfire.net/index.jsp

**Description:** The 'Server Leaks Version Information via 'Server' HTTP Response Header Field' vulnerability is a serious security issue that can be exploited by attackers to find potential weaknesses in a web application.

**PoC (Proof of Concept):**

	Step1: Go to http://testfire.net/index.jsp
	
	Step2: Then open Burp Suite and then connect Burp Suite and capture
	
	Step3: Then send Repeater
	
	Step 4: Then Request send and see Response

**Snapshots/Screenshot:**

![ss-9](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/3b604378-037e-4fda-95df-985da70fccd1)

**Recommendation/Mitigation/Remediation:**

	Disable or Customize Server Headers
	
	Use Web Application Firewalls (WAFs)


## **Vulnerability 08**

**Vulnerability Title:** X Content Type Options Header Missing

**Severity:** Low

**Vulnerable URL:** http://testfire.net/index.jsp

**Description:** The 'X-Content-Type-Options Header Missing' vulnerability is a common security issue in web applications. This vulnerability arises when a web server doesn't set the 'X-Content-TypeOptions' header in its response, allowing attackers to perform content-type sniffing attacks.

**PoC (Proof of Concept):**

	Step1: Go to http://testfire.net/index.jsp
	
	Step2: Then open Burp Suite and then connect Burp Suite and capture
	
	Step3: Then send Repeater

	Step 4: Then Request send and see Response

**Snapshots/Screenshot:**

![ss-9](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/6118b4ea-90c7-41e2-ad45-a476303adc16)

**Recommendation/Mitigation/Remediation:**

	Enable X-Content-Type-Options Header
	
	Content Security Policy (CSP)


## **Vulnerability 09**

**Vulnerability Title:** Information Disclosure

**Severity:** Low

**Vulnerable URL:** http://testfire.net/login.jsp

**Description:** Information disclosure, also known as information leakage, is when a website unintentionally reveals sensitive information to its users.

**PoC (Proof of Concept):**

	Step1: Go to http://testfire.net/login.jsp
	
	Step2: Then open Burp Suite and then connect Burp Suite and capture
	
	Step3: Then send Repeater
	
	Step 4: Then Request send and see Response

**Snapshots/Screenshot:**

![ss-10](https://github.com/sayan-125/Altoro-Mutual/assets/158836588/6343a7f2-dd65-490f-9e92-6f4d1f8d8fce)

**Recommendation/Mitigation/Remediation:**

	Data Classification and Risk Assessment
	
	Access Controls and Authorization
