---
geometry: margin=2cm
header-includes: |
  \usepackage{fvextra}
  \DefineVerbatimEnvironment{Highlighting}{Verbatim}{breaklines,commandchars=\\\{\},breaksymbol=}
  \definecolor{bg}{HTML}{f2f2f2}
  \pagecolor{bg}
---

# Notes

- Additional properties on the system were not enabled. This makes the system consistent with the online demo at <http://demo.testfire.net/> and hence the exploits will also work there. Enabling the additional properties does introduce other vulnerabilities, but I have already found 23 vulnerabilities.
- If you want to test on <http://demo.testfire.net/> or on your local instance, make sure to replace the `/altoromutual` part in the URLs in the exploits in the JavaScript scripts to the base path on which the website is hosted. For example, in case of the <http://demo.testfire.net/>, there is no base path so the `/altoromutual` part of the URL has to be removed in the scripts.
- Code patches are applied in the order they appear.
- The system provides an additional API (we'll refer to it as the REST API) in addition to the API the frontend uses to communicate with the backend. Some same vulnerabilities are discovered through both APIs; these are not duplicates. They are two entry points to the same vulnerability and should be tested separately.
- Finding details are high-level, low-detail descriptions of the vulnerabilities.
- Finding scenarios contain the testing steps, vulnerability causes, fix explanation, fix patch and re-test steps.

# Findings List

| Name                                                                                                   | Original severity | CVSS Score | After re-test severity |
| ------------------------------------------------------------------------------------------------------ | ----------------- | ---------- | ---------------------- |
| SQL injection in log in                                                                                | Critical          | 9.3        | Resolved               |
| SQL injection in REST API (accounts)                                                                   | High              | 8.7        | Resolved               |
| SQL injection in transactions listing                                                                  | High              | 7.1        | Resolved               |
| SQL injection in REST API (transactions)                                                               | High              | 7.1        | Resolved               |
| Unauthorized file access (`Q3_earnings.rtf`)                                                           | High              | 8.7        | Resolved               |
| Unauthorized file access (`Draft.rtf`)                                                                 | High              | 8.7        | Resolved               |
| Path traversal attack                                                                                  | Critical          | 9.2        | Resolved               |
| Exploiting business logic flaw (excessive money transfer)                                              | High              | 7.1        | Resolved               |
| Exploiting business logic flaw (excessive money transfer in REST API)                                  | High              | 7.1        | Resolved               |
| Exploiting business logic flaw (negative money transfer in REST API)                                   | High              | 7.1        | Resolved               |
| Bypassing access control (sending money from a foreign account in the REST API)                        | High              | 7.1        | Resolved               |
| Bypassing access control (sending money from a foreign account through cookie manipulation)            | High              | 7.1        | Resolved               |
| Bypassing access control (viewing a foreign account details)                                           | High              | 7.1        | Resolved               |
| Bypassing access control (getting a foreign account details through the REST API)                      | High              | 7.1        | Resolved               |
| Bypassing access control (getting the last ten transactions of a foreign account through the REST API) | High              | 7.1        | Resolved               |
| Bypassing access control (accessing admin pages)                                                       | High              | 8.6        | Resolved               |
| Cross site scripting in `/bank/customize.jsp`                                                          | High              | 7.1        | Resolved               |
| Cross site scripting in `/search.jsp`                                                                  | High              | 7.1        | Resolved               |
| Cross site scripting in `/util/serverStatusCheckService.jsp`                                           | High              | 7.1        | Resolved               |
| Cross site scripting in `/bank/queryxpath.jsp`                                                         | High              | 7.1        | Resolved               |
| Cross site scripting in `/bank/transaction.jsp`                                                        | High              | 7.1        | Resolved               |
| Cross site scripting in `/bank/feedbacksuccess.jsp`                                                    | High              | 7.1        | Resolved               |
| Unvalidated redirect in `/bank/customize.jsp`                                                          | Medium            | 5.3        | Resolved               |

# Findings details

## SQL injection in log in

- **Test CVSS severity**: critical
- **Test CVSS score:** 9.3
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/SQL_Injection>
- **Description of the vulnerability:** an attacker can bypass the correct username/password check in the login by having the username as `asd' or 1=1 --` and the password as anything.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to bypass login
- **Recommendations:** use prepared statements instead of interpolating user inputs in the login SQL queries

## SQL injection in REST API (accounts)

- **Test CVSS severity**: High
- **Test CVSS score:** 8.7
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/SQL_Injection>
- **Description of the vulnerability:** an attacker can list all bank accounts on the system by passing the username as `asd' or 1=1 --` in the rest api authentication token and submitting a GET request to `/api/account`.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to list all bank accounts on the system
- **Recommendations:** use prepared statements instead of interpolating user inputs in the listing bank accounts SQL queries and in the authentication queries

## SQL injection in transactions listing

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/SQL_Injection>
- **Description of the vulnerability:** an attacker can list all transactions on the system by bypassing the front-end validation in the transactions filtering page and setting the start date as `2018-06-11` and the end date as `2018-06-11 23:59:59') OR 1=1 --`
- **Impact:** severe impact; successful exploitation gives the attacker the ability to list all transactions on the system
- **Recommendations:** use prepared statements instead of interpolating user inputs in the transactions listing SQL queries

## SQL injection in REST API (transactions)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/SQL_Injection>
- **Description of the vulnerability:** an attacker can list all transactions on the system by setting the start date as `2018-06-11` and the end date as `2018-06-11 23:59:59') OR 1=1 --` in the transaction listing REST API endpoint (`POST /api/account/800004/transactions`)
- **Impact:** severe impact; successful exploitation gives the attacker the ability to list all bank accounts on the system
- **Recommendations:** use prepared statements instead of interpolating user inputs in the listing bank accounts SQL queries and in the authentication queries

## Unauthorized file access (`Q3_earnings.rtf`)

- **Test CVSS severity**: High
- **Test CVSS score:** 8.7
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** An attacker can access a file they should not be allowed to access
- **Description of the vulnerability:** an attacker can download the bank's confidential earnings via visiting `/pr/Q3_earnings.rtf`.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to download the bank's confidential earnings
- **Recommendations:** put the earnings file in a directory that is not served on the internet

## Unauthorized file access (`Draft.rtf`)

- **Test CVSS severity**: High
- **Test CVSS score:** 8.7
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** An attacker can access a file they should not be allowed to access
- **Description of the vulnerability:** an attacker can download the bank's confidential draft via visiting `/pr/Draft.rtf`.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to download the bank's confidential draft
- **Recommendations:** put the draft file in a directory that is not served on the internet

## Path traversal attack

- **Test CVSS severity**: Critical
- **Test CVSS score:** 9.2
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/Path_Traversal>
- **Description of the vulnerability:** an attacker can access configuration files that can contain secrets under `WebContent/WEB-INF` by going to `/index.jsp?content=../WEB-INF/name_of_the_file` (e.g, `/index.jsp?content=../WEB-INF/app.properties`)
- **Impact:** severe impact; successful exploitation gives the attacker the ability to access configuration files in the `WebContent/WEB-INF` directory which can contain passwords.
- **Recommendations:** make sure paths served in `index.jsp` do not escape the parent directory (follow OWASP's recommendations in the link above).

## Exploiting business logic flaw (excessive money transfer)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the business logic (lack of input validation)
- **Description of the vulnerability:** an attacker can transfer an amount (AM) of money from their account (A) to their other account (B) even if the amount (AM) exceeds the balance in account (A).
- **Impact:** severe impact; successful exploitation gives the attacker the ability to put an unlimited amount of money on one of their accounts and put a negative amount of money on another one of their accounts.
- **Recommendations:** make sure the user can not transfer an amount of money that is larger than his account's balance

## Exploiting business logic flaw (excessive money transfer in REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the business logic (lack of REST API request body validation)
- **Description of the vulnerability:** an attacker can transfer an amount (AM) of money from their account (A) to their other account (B) even if the amount (AM) exceeds the balance in account (A) through the `POST /api/transfer` REST API endpoint.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to put an unlimited amount of money on one of their accounts and put a negative amount of money on another one of their accounts.
- **Recommendations:** make sure the user can not transfer an amount of money that is larger than his account's balance through the REST API

## Exploiting business logic flaw (negative money transfer in REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the business logic (lack of REST API request body validation)
- **Description of the vulnerability:** an attacker can transfer a negative amount of money from their account to another account through the `POST /api/transfer` REST API endpoint.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to transfer a negative amount of money from an account to another leading to an decrease of money in the receiving account and a increase of money in the sending account
- **Recommendations:** make sure the user can not transfer a negative amount of money through the REST API

## Bypassing access control (sending money from a foreign account in the REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the access control (lack of REST API request body validation)
- **Description of the vulnerability:** an attacker can transfer an amount of money from accounts that do not belong to them through the `POST /api/transfer` REST API endpoint.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to transfer an amount of money from accounts that do not belong to them
- **Recommendations:** make sure the user can only transfer money from their accounts

## Bypassing access control (sending money from a foreign account through cookie manipulation)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the access control (treating cookies as a trusted source of truth of the authorities)
- **Description of the vulnerability:** an attacker can transfer an amount of money from accounts that do not belong to them by modifying a cookie that represents what accounts belong to the user
- **Impact:** severe impact; successful exploitation gives the attacker the ability to transfer an amount of money from accounts that do not belong to them
- **Recommendations:** either do not use cookies for determining what accounts belong to the user, or add a verification signature to the cookie.

## Bypassing access control (viewing a foreign account details)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the access control (not doing backend validation on who is viewing the account)
- **Description of the vulnerability:** an attacker can view the account details of another user through the `/bank/showAccount` page
- **Impact:** severe impact; successful exploitation gives the attacker the ability to view the details of foreign accounts violating their privacy
- **Recommendations:** do backend validation before sending the data to the `/bank/showAccount` page

## Bypassing access control (getting a foreign account details through the REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the access control (not validating who is GET'ing the account in the REST API)
- **Description of the vulnerability:** an attacker can view the account details of another user through the `GET /api/account` endpoint
- **Impact:** severe impact; successful exploitation gives the attacker the ability to view the details foreign accounts violating their privacy
- **Recommendations:** do proper access control in the `GET /api/account` endpoint

## Bypassing access control (getting the last ten transactions of a foreign account through the REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the access control (not validating who is GET'ing the last ten transactions of an account in the REST API)
- **Description of the vulnerability:** an attacker can view the last ten transactions of an account of another user through the `GET /api/account/{accountNo}/transactions` endpoint
- **Impact:** severe impact; successful exploitation gives the attacker the ability to view the last ten transactions of foreign accounts violating their privacy
- **Recommendations:** do proper access control in the `GET /api/account/{accountNo}/transactions` endpoint

## Bypassing access control (accessing admin pages)

- **Test CVSS severity**: High
- **Test CVSS score:** 8.6
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** a defect in the access control (improper validation on who is accessing the admin pages)
- **Description of the vulnerability:** an attacker can view the admin pages and take admin actions by visiting `/admin/admin.jsp`
- **Impact:** severe impact; successful exploitation gives the attacker admin privileges
- **Recommendations:** do proper access control on admin pages and actions

## Cross site scripting in `/bank/customize.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `lang` parameter in `/bank/customize.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but the page can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

## Cross site scripting in `/search.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `query` parameter in `/search.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but the page can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

## Cross site scripting in `/util/serverStatusCheckService.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `HostName` parameter in `/util/serverStatusCheckService.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but the page can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

## Cross site scripting in `/bank/queryxpath.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `content` parameter in `/bank/queryxpath.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but the page can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

## Cross site scripting in `/bank/transaction.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `startDate` or `endDate` parameter in `/bank/transaction.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but the page can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

## Cross site scripting in `/bank/feedbacksuccess.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `email_addr` parameter in `/bank/feedbacksuccess.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but the page can contain an form that can cause the victim's data to be stolen
- **Recommendations:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

## Unvalidated redirect in `/bank/customize.jsp`

- **Test CVSS severity**: Medium
- **Test CVSS score:** 5.3
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **After re-test severity:** resolved
- **Description of the type of the vulnerability:** <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>
- **Description of the vulnerability:** an attacker can redirect the user to an arbitrary site by putting the website in the value of the `content` parameter in `/bank/customize.jsp`
- **Impact:** medium impact; an attacker can send such link to other users; the link appears as if it is genuine but it can redirect the user to a phishing website and possibly steal their data
- **Recommendations:** <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>

# Finding scenarios

<!-- TODO: Fixing steps, re-test steps -->

## SQL injection in log in

### Test steps

- Open /login.jsp
- Login with the username as: `asd' or 1=1 --`, and the password as anything:

![Log in injected](test-images/image-2.png)

- Observe that you are logged in as the first user in the system:

![After log in injected](test-images/image-1.png)

### Cause

`DBUtil.isValidUser()` method interpolates the user input in the SQL query; hence making the attacker able to execute arbitrary queries. The resulting query becomes:

```sql
SELECT COUNT(*) FROM PEOPLE WHERE USER_ID = 'asd' or 1=1 -- AND PASSWORD='anything'")
```

### Fix explanation

Prepared statements with parameters setting are used in `DBUtil.isValidUser()` instead of string concatenation to form the query.

### Fix patch

```diff
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
index 3031aa8..c7df6a3 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
@@ -29,6 +29,7 @@ import java.util.ArrayList;
 import javax.naming.Context;
 import javax.naming.InitialContext;
 import javax.sql.DataSource;
+import java.sql.PreparedStatement;

 import com.ibm.security.appscan.Log4AltoroJ;
 import com.ibm.security.appscan.altoromutual.model.Account;
@@ -214,16 +215,16 @@ public class DBUtil {
 			return false;

 		Connection connection = getConnection();
-		Statement statement = connection.createStatement();
-
-		ResultSet resultSet =statement.executeQuery("SELECT COUNT(*)FROM PEOPLE WHERE USER_ID = '"+ user +"' AND PASSWORD='" + password + "'"); /* BAD - user input should always be sanitized */
-
-		if (resultSet.next()){
-
+		try (PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM PEOPLE WHERE USER_ID = ? AND PASSWORD = ?")) {
+			statement.setString(1, user);
+			statement.setString(2, password);
+			ResultSet resultSet = statement.executeQuery();
+			if (resultSet.next()){
 				if (resultSet.getInt(1) > 0)
 					return true;
+			}
+			return false;
 		}
-		return false;
 	}
```

### Re-test steps

Enter the same credentials as the test steps and observe how the system says the username or password is incorrect:

![Incorrect credentials instead of sql injection](retest-images/image.png)

## SQL injection in REST API (accounts)

### Test steps

- Run the following script in your browser's dev tools' console while on the website (F12 > console):

  ```javascript
  username = "asd' or 1=1 --";
  password = 'asd';
  res = await (
    await fetch('/altoromutual/api/login', {
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      body: JSON.stringify({
        username,
        password
      })
    })
  ).json();

  auth = res.Authorization;

  await (
    await fetch('/altoromutual/api/account', {
      headers: { Authorization: auth }
    })
  ).json();
  ```

- Observe how all bank accounts are returned:

![All bank accounts returned from REST API](test-images/image-3.png)

### Cause

- `DBUtil.getUserInfo()` method interpolates the user input in the SQL query; hence making the attacker able to execute arbitrary queries. The resulting query becomes:
  ```sql
  SELECT FIRST_NAME,LAST_NAME,ROLE FROM PEOPLE WHERE USER_ID = 'asd' or 1=1 --
  ```
- `DBUtil.getUserInfo()` returns the received username in the parameter rather than the one retrieved from the database (since it assumes they would be the same)
- `DBUtil.getAccounts()` is then called with the modified username and also interpolates the SQL query with the user input; hence the resulting query becomes:
  ```sql
  SELECT ACCOUNT_ID, ACCOUNT_NAME, BALANCE FROM ACCOUNTS WHERE USERID = 'asd' or 1=1 --
  ```
  leading to returning all of the users in the database

### Fix explanation

Use prepared statements with parameter setting in `DBUtil.getUserInfo()` and `DBUtil.getAccounts()`.

### Fix patch

```diff
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
index c7df6a3..0de05f2 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
@@ -238,17 +238,19 @@ public class DBUtil {
 		if (username == null || username.trim().length() == 0)
 			return null;

-		Connection connection = getConnection();
-		Statement statement = connection.createStatement();
-		ResultSet resultSet =statement.executeQuery("SELECT FIRST_NAME,LAST_NAME,ROLE FROM PEOPLE WHERE USER_ID = '"+ username +"' "); /* BAD - user input should always be sanitized */
-
 		String firstName = null;
 		String lastName = null;
 		String roleString = null;
-		if (resultSet.next()){
-			firstName = resultSet.getString("FIRST_NAME");
-			lastName = resultSet.getString("LAST_NAME");
-			roleString = resultSet.getString("ROLE");
+
+		Connection connection = getConnection();
+		try (PreparedStatement statement = connection.prepareStatement("SELECT FIRST_NAME,LAST_NAME,ROLE FROM PEOPLE WHERE USER_ID = ?")) {
+			statement.setString(1, username);
+			ResultSet resultSet = statement.executeQuery();
+			if (resultSet.next()){
+				firstName = resultSet.getString("FIRST_NAME");
+				lastName = resultSet.getString("LAST_NAME");
+				roleString = resultSet.getString("ROLE");
+			}
 		}

 		if (firstName == null || lastName == null)
@@ -273,19 +275,21 @@ public class DBUtil {
 			return null;

 		Connection connection = getConnection();
-		Statement statement = connection.createStatement();
-		ResultSet resultSet =statement.executeQuery("SELECT ACCOUNT_ID, ACCOUNT_NAME, BALANCE FROM ACCOUNTS WHERE USERID = '"+ username +"' "); /* BAD - user input should always be sanitized */
+		try (PreparedStatement statement = connection.prepareStatement("SELECT ACCOUNT_ID, ACCOUNT_NAME, BALANCE FROM ACCOUNTS WHERE USERID = ?")) {
+			statement.setString(1, username);
+			ResultSet resultSet = statement.executeQuery();

-		ArrayList<Account> accounts = new ArrayList<Account>(3);
-		while (resultSet.next()){
-			long accountId = resultSet.getLong("ACCOUNT_ID");
-			String name = resultSet.getString("ACCOUNT_NAME");
-			double balance = resultSet.getDouble("BALANCE");
-			Account newAccount = new Account(accountId, name, balance);
-			accounts.add(newAccount);
+			ArrayList<Account> accounts = new ArrayList<Account>(3);
+			while (resultSet.next()){
+				long accountId = resultSet.getLong("ACCOUNT_ID");
+				String name = resultSet.getString("ACCOUNT_NAME");
+				double balance = resultSet.getDouble("BALANCE");
+				Account newAccount = new Account(accountId, name, balance);
+				accounts.add(newAccount);
+			}
+
+			return accounts.toArray(new Account[accounts.size()]);
 		}
-
-		return accounts.toArray(new Account[accounts.size()]);
 	}

 	/**
```

### Re-test steps

- Run the same script as the one in the test steps and observe how the API returns an error instead

![alt text](retest-images/image-1.png)

- Run the following script to try to evade the login endpoint by setting the authorization token manually and observe how the API also returns an error:

![alt text](retest-images/image-2.png)

## SQL injection in transactions listing

### Test steps

- Go to `/bank/transaction.jsp`
- Run the following javascript code in the browser console while on the page (F12 > console) to bypass front-end validation:

  ```javascript
  Form1.onsubmit = undefined;
  ```

![Bypass transactions filtering frontend validation](test-images/image.png)

- Set the start date as `2018-06-11` and the end date as `2018-06-11 23:59:59') OR 1=1 --`:

![Setting the start date and the end date of transactions filtering](test-images/image-4.png)

- Click submit and observe how all of the transactions on the system are shown:

![All of the transactions on the system are shown](test-images/image-5.png)

### Cause

`DBUtil.getTransactions()` method interpolates the user input in the SQL query; hence making the attacker able to execute arbitrary queries. The resulting query becomes:

```sql
SELECT * FROM TRANSACTIONS WHERE (ACCOUNTID = "whatever" OR ACCOUNTID = "whatever") AND (DATE BETWEEN '2018-06-11' AND '2018-06-11 23:59:59') OR 1=1 --') ORDER BY DATE DESC
```

### Fix explanation

Use prepared statements with parameter setting in `DBUtil.getTransactions()`.

### Fix patch

```diff
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
index 0de05f2..aa3bd9d 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
@@ -377,43 +377,46 @@ public class DBUtil {
 		if (accounts == null || accounts.length == 0)
 			return null;

-			Connection connection = getConnection();
+		StringBuffer acctIds = new StringBuffer();
+		acctIds.append("ACCOUNTID = ?");
+		for (int i=1; i<accounts.length; i++){
+			acctIds.append(" OR ACCOUNTID = ?");
+		}
+
+		String dateString = null;
+		boolean startDateExists = false;
+		boolean endDateExists = false;
+
+		if (startDate != null && startDate.length()>0 && endDate != null && endDate.length()>0){
+			startDateExists = true;
+			endDateExists = true;
+			dateString = "DATE BETWEEN ? AND ?";
+		} else if (startDate != null && startDate.length()>0){
+			startDateExists = true;
+			dateString = "DATE > ?";
+		} else if (endDate != null && endDate.length()>0){
+			endDateExists = true;
+			dateString = "DATE < ?";
+		}
+
+		String query = "SELECT * FROM TRANSACTIONS WHERE (" + acctIds.toString() + ") " + ((dateString==null)?"": "AND (" + dateString + ") ") + "ORDER BY DATE DESC" ;
+		ArrayList<Transaction> transactions = new ArrayList<Transaction>();

-
-			Statement statement = connection.createStatement();
-
+		Connection connection = getConnection();
+		try (PreparedStatement statement = connection.prepareStatement(query)) {
 			if (rowCount > 0)
 				statement.setMaxRows(rowCount);
-
-			StringBuffer acctIds = new StringBuffer();
-			acctIds.append("ACCOUNTID = " + accounts[0].getAccountId());
-			for (int i=1; i<accounts.length; i++){
-				acctIds.append(" OR ACCOUNTID = "+accounts[i].getAccountId());
+			int i = 1;
+			for (; i<=accounts.length; i++){
+				statement.setString(i, String.valueOf(accounts[i - 1].getAccountId()));
 			}
-
-			String dateString = null;
-
-			if (startDate != null && startDate.length()>0 && endDate != null && endDate.length()>0){
-				dateString = "DATE BETWEEN '" + startDate + " 00:00:00' AND '" + endDate + " 23:59:59'";
-			} else if (startDate != null && startDate.length()>0){
-				dateString = "DATE > '" + startDate +" 00:00:00'";
-			} else if (endDate != null && endDate.length()>0){
-				dateString = "DATE < '" + endDate + " 23:59:59'";
+			if (startDateExists) {
+				statement.setString(i++, startDate + " 00:00:00");
 			}
-
-			String query = "SELECT * FROM TRANSACTIONS WHERE (" + acctIds.toString() + ") " + ((dateString==null)?"": "AND (" + dateString + ") ") + "ORDER BY DATE DESC" ;
-			ResultSet resultSet = null;
-
-			try {
-				resultSet = statement.executeQuery(query);
-			} catch (SQLException e){
-				int errorCode = e.getErrorCode();
-				if (errorCode == 30000)
-					throw new SQLException("Date-time query must be in the format of yyyy-mm-dd HH:mm:ss", e);
-
-				throw e;
+			if (endDateExists) {
+				statement.setString(i++, endDate + " 23:59:59");
 			}
-			ArrayList<Transaction> transactions = new ArrayList<Transaction>();
+			ResultSet resultSet = statement.executeQuery();
 			while (resultSet.next()){
 				int transId = resultSet.getInt("TRANSACTION_ID");
 				long actId = resultSet.getLong("ACCOUNTID");
@@ -422,8 +425,14 @@ public class DBUtil {
 				double amount = resultSet.getDouble("AMOUNT");
 				transactions.add(new Transaction(transId, actId, date, desc, amount));
 			}
-
-			return transactions.toArray(new Transaction[transactions.size()]);
+		} catch (SQLException e){
+			int errorCode = e.getErrorCode();
+			if (errorCode == 20000)
+				throw new SQLException("Date-time query must be in the format of yyyy-mm-dd HH:mm:ss", e);
+			throw e;
+		}
+
+		return transactions.toArray(new Transaction[transactions.size()]);
 	}

 	public static String[] getBankUsernames() {
```

### Re-test steps

Run the same test steps and notice how the server returns an error about the incorrect date format instead:

![alt text](retest-images/image-3.png)

## SQL injection in REST API (transactions)

### Test steps

Run the following script while on the website (F12 > console), and observe how all transactions on the system are listed:

```javascript
username = 'jdoe';
password = 'demo1234';
res = await (
  await fetch('/altoromutual/api/login', {
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
    body: JSON.stringify({
      username,
      password
    })
  })
).json();

auth = res.Authorization;

res = await (
  await fetch('/altoromutual/api/account/800004/transactions', {
    headers: { 'Content-Type': 'application/json', Authorization: auth },
    method: 'POST',
    body: JSON.stringify({
      startDate: '2018-06-11',
      endDate: "2018-06-11 23:59:59') OR 1=1 --"
    })
  })
).json();
```

![Listing all of the transactions on the system through the REST API](test-images/image-38.png)

### Cause

`DBUtil.getTransactions()` method interpolates the user input in the SQL query; hence making the attacker able to execute arbitrary queries. The resulting query becomes:

```sql
SELECT * FROM TRANSACTIONS WHERE (ACCOUNTID = "whatever" OR ACCOUNTID = "whatever") AND (DATE BETWEEN '2018-06-11' AND '2018-06-11 23:59:59') OR 1=1 --') ORDER BY DATE DESC
```

### Fix explanation

Fixed by fixing the previous vulnerability since it shared the same vulnerable code.

### Fix patch

Fixed by fixing the previous vulnerability since it shared the same vulnerable code.

### Re-test steps

Run the same script in the test steps and observe how the server returns an error instead:

![alt text](retest-images/image-4.png)

## Unauthorized file access (`Q3_earnings.rtf`)

### Test steps

- Click on "INSIDE ALTORO MUTUAL":

![Inside Altoro Mutual](test-images/image-6.png)

- Click on "2006 community annual report":

![2006 community annual report](test-images/image-7.png)

- Change the last part of the URL to `Q3_earning.rtf`:

![Q3 earnings download](test-images/image-8.png)

- Download and view the file:

![Q3 earnings](test-images/image-9.png)

### Cause

Everything under the `WebContent` directory and not in the `WEB-INF` directory is served by Tomcat.

### Fix explanation

Move the `Q3_earnings.rtf` file outside of the `WebContent` directory.

### Fix patch

```diff
diff --git a/src/WebContent/pr/Q3_earnings.rtf b/src/confidential/Q3_earnings.rtf
similarity index 100%
rename from src/WebContent/pr/Q3_earnings.rtf
rename to src/confidential/Q3_earnings.rtf
```

### Re-test steps

Do the same test steps and observe how the server returns a "not found" error instead:

![alt text](retest-images/image-5.png)

## Unauthorized file access (`Draft.rtf`)

### Test steps

- Click on "INSIDE ALTORO MUTUAL":

![Inside Altoro Mutual](test-images/image-6.png)

- Click on "2006 community annual report":

![2006 community annual report](test-images/image-7.png)

- Change the last part of the URL to `Draft.rtf`:

![Draft download](test-images/image-10.png)

- Download and view the file:

![Draft](test-images/image-11.png)

### Cause

Everything under the `WebContent` directory and not in the `WEB-INF` directory is served by Tomcat.

### Fix explanation

Move the `Draft.rtf` file outside of the `WebContent` directory.

### Fix patch

```diff
diff --git a/src/WebContent/pr/Draft.rtf b/src/confidential/Draft.rtf
similarity index 100%
rename from src/WebContent/pr/Draft.rtf
rename to src/confidential/Draft.rtf
```

### Re-test steps

Do the same test steps and observe how the server returns a "not found" error instead:

![alt text](retest-images/image-6.png)

## Path traversal attack

### Test steps

- Visit `/index.jsp?content=../WEB-INF/app.properties` and observe an application configuration file get leaked

![app.properties getting leaked](test-images/image-12.png)

- Visit `/index.jsp?content=../WEB-INF/web.xml` and observe an application configuration file get leaked

![web.xml getting leaked](test-images/image-13.png)

### Cause

In `index.jsp`, content is served from the `static/` directory using user provided subdirectories which can include dot-dot-slashes (`../`)

### Fix explanation

In `index.jsp`, if the resulting path's base directory is not `static/`, return the `static/default.htm` page.

### Fix patch

```diff
diff --git a/src/WebContent/index.jsp b/src/WebContent/index.jsp
index f3e30b1..a00e710 100644
--- a/src/WebContent/index.jsp
+++ b/src/WebContent/index.jsp
@@ -1,4 +1,6 @@
 <%@page import="java.io.BufferedReader"%>
+<%@page import="java.nio.file.Paths"%>
+<%@page import="java.nio.file.Path"%>
 <%@page import="java.io.InputStream"%>
 <%@page import="java.io.InputStreamReader"%>
 <%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil"%>
@@ -94,7 +96,13 @@ IBM AltoroJ
 	 		<% } %>
 		<%
 		} else {
-			content = "static/"+content;
+			String basePath = "static";
+			Path resolved = Paths.get(basePath).resolve(content).normalize();
+			System.out.println(resolved);
+			if (resolved.startsWith(basePath))
+				content = resolved.toString();
+			else
+				content = "static/default.htm";
 		%>

 		<%  try { %>
```

The debugging message was removed in a later patch.

### Re-test steps

- Visit `/index.jsp?content=../WEB-INF/app.properties` and observe how the server returns the default page:

![alt text](retest-images/image-7.png)

- Visit `/index.jsp?content=../WEB-INF/web.xml` and observe how the server returns the default page:

![alt text](retest-images/image-8.png)

## Exploiting business logic flaw (excessive money transfer)

### Test steps

- Go to `View Account Summary`:

![View account summary](test-images/image-14.png)

- Select an account (A) and make note of the available balance:

![A available balance](test-images/image-15.png)

- Select an account (B) and make note of the available balance:

![B available balance](test-images/image-18.png)

- Go to `Transfer Funds`, change the `To Account` and make note of it, enter an amount that is larger than the balance, click `Transfer Money`:

![Transferring funds](test-images/image-16.png)

- Click `Transfer Money` and notice how the operation succeeds:

![Transferring funds succeeded](test-images/image-17.png)

- View the available balance in account (A) and notice how it becomes negative:

![Negative balance](test-images/image-19.png)

- View the available balance in account (B) and notice how it increases:

![Increased balance](test-images/image-20.png)

### Cause

`OperationsUtil.doServletTransfer` does not check the available balance.

### Fix explanation

Check the originating account balance in `OperationsUtil.doServletTransfer`. Also don't use cookies as a source of truth of the user's accounts and their balances since they can be modified on the client side (this also fixes a later vulnerability).

### Fix patch

```diff
diff --git a/src/src/com/ibm/security/appscan/altoromutual/model/Account.java b/src/src/com/ibm/security/appscan/altoromutual/model/Account.java
index 2c4be12..03087dd 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/model/Account.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/model/Account.java
@@ -72,50 +72,4 @@ public class Account {
 	public String getAccountName() {
 		return accountName;
 	}
-
-	public static Account[] fromBase64List (String b64accounts){
-		String accounts = new String(Base64.decodeBase64(b64accounts));
-
-		StringTokenizer outerTokens = new StringTokenizer(accounts, "|");
-		ArrayList<Account> accountList = new ArrayList<Account>();
-
-		while (outerTokens.hasMoreTokens()){
-			StringTokenizer tokens = new StringTokenizer(outerTokens.nextToken(), "~");
-
-			long acctId = -1;
-			String acctName = null;
-			double amt = Double.MAX_VALUE;
-			if (tokens.hasMoreTokens())
-				acctId = Long.valueOf(tokens.nextToken());
-
-			if (tokens.hasMoreTokens())
-				acctName = tokens.nextToken();
-
-			if (tokens.hasMoreTokens())
-				amt = Double.valueOf(tokens.nextToken());
-
-			if (acctId > -1 && acctName != null && amt != Double.MAX_VALUE){
-				accountList.add(new Account(acctId, acctName, amt));
-			}
-		}
-
-		return (accountList.toArray(new Account[accountList.size()]));
-	}
-
-	public static String toBase64List(Account[] accounts){
-
-		StringBuffer accountList = new StringBuffer();
-
-		for (Account account:accounts){
-			accountList.append(account.getAccountId());
-			accountList.append("~");
-			accountList.append(account.getAccountName());
-			accountList.append("~");
-			accountList.append(account.getBalance());
-			accountList.append("|");
-		}
-
-		return Base64.encodeBase64String(accountList.toString().getBytes());
-
-	}
 }
diff --git a/src/src/com/ibm/security/appscan/altoromutual/servlet/LoginServlet.java b/src/src/com/ibm/security/appscan/altoromutual/servlet/LoginServlet.java
index 55303c3..7216b87 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/servlet/LoginServlet.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/servlet/LoginServlet.java
@@ -20,7 +20,6 @@ package com.ibm.security.appscan.altoromutual.servlet;
 import java.io.IOException;

 import javax.servlet.ServletException;
-import javax.servlet.http.Cookie;
 import javax.servlet.http.HttpServlet;
 import javax.servlet.http.HttpServletRequest;
 import javax.servlet.http.HttpServletResponse;
@@ -89,10 +88,8 @@ public class LoginServlet extends HttpServlet {
 			return;
 		}

-		//Handle the cookie using ServletUtil.establishSession(String)
 		try{
-			Cookie accountCookie = ServletUtil.establishSession(username,session);
-			response.addCookie(accountCookie);
+			ServletUtil.establishSession(username,session);
 			response.sendRedirect(request.getContextPath()+"/bank/main.jsp");
 			}
 		catch (Exception ex){
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
index 5629335..a481b6a 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
@@ -6,7 +6,6 @@ import java.text.SimpleDateFormat;
 import java.util.Date;
 import java.util.Random;
 import java.util.StringTokenizer;
-import javax.servlet.http.Cookie;
 import javax.servlet.http.HttpServletRequest;
 import org.apache.commons.codec.binary.Base64;
 import org.apache.commons.lang.StringEscapeUtils;
@@ -39,31 +38,15 @@ public class OperationsUtil {
 	public static String doServletTransfer(HttpServletRequest request, long creditActId, String accountIdString,
 			double amount) {

-		long debitActId = 0;
+		Account debitAct = null;

 		User user = ServletUtil.getUser(request);
 		String userName = user.getUsername();

 		try {
 			Long accountId = -1L;
-			Cookie[] cookies = request.getCookies();
-
-			Cookie altoroCookie = null;
-
-			for (Cookie cookie: cookies){
-				if (ServletUtil.ALTORO_COOKIE.equals(cookie.getName())){
-					altoroCookie = cookie;
-					break;
-				}
-			}
-
-			Account[] cookieAccounts = null;
-			if (altoroCookie == null)
-				cookieAccounts = user.getAccounts();
-			else
-				cookieAccounts = Account.fromBase64List(altoroCookie.getValue());
-

+			Account[] accounts = user.getAccounts();

 			try {
 				accountId = Long.parseLong(accountIdString);
@@ -72,16 +55,16 @@ public class OperationsUtil {
 			}

 			if (accountId > 0) {
-				for (Account account: cookieAccounts){
+				for (Account account: accounts){
 					if (account.getAccountId() == accountId){
-						debitActId = account.getAccountId();
+						debitAct = account;
 						break;
 					}
 				}
 			} else {
-				for (Account account: cookieAccounts){
+				for (Account account: accounts){
 					if (account.getAccountName().equalsIgnoreCase(accountIdString)){
-						debitActId = account.getAccountId();
+						debitAct = account;
 						break;
 					}
 				}
@@ -95,22 +78,23 @@ public class OperationsUtil {
 		String message = null;
 		if (creditActId < 0){
 			message = "Destination account is invalid";
-		} else if (debitActId < 0) {
+		} else if (debitAct == null) {
 			message = "Originating account is invalid";
 		} else if (amount < 0){
 			message = "Transfer amount is invalid";
+		} else if (amount > debitAct.getBalance()){
+			message = "Insufficient balance in originating account";
 		}

 		//if transfer amount is zero then there is nothing to do
 		if (message == null && amount > 0){
-			//Notice that available balance is not checked
-			message = DBUtil.transferFunds(userName, creditActId, debitActId, amount);
+			message = DBUtil.transferFunds(userName, creditActId, debitAct.getAccountId(), amount);
 		}

 		if (message != null){
 			message = "ERROR: " + message;
 		} else {
-			message = amount + " was successfully transferred from Account " + debitActId + " into Account " + creditActId + " at " + new SimpleDateFormat().format(new Date()) + ".";
+			message = amount + " was successfully transferred from Account " + debitAct.getAccountId() + " into Account " + creditActId + " at " + new SimpleDateFormat().format(new Date()) + ".";
 		}

 		return message;
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/ServletUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/ServletUtil.java
index 6524e35..81fb326 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/ServletUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/ServletUtil.java
@@ -34,7 +34,6 @@ import java.util.StringTokenizer;
 import java.util.regex.Pattern;

 import javax.servlet.ServletContext;
-import javax.servlet.http.Cookie;
 import javax.servlet.http.HttpServletRequest;
 import javax.servlet.http.HttpSession;
 import javax.xml.parsers.DocumentBuilderFactory;
@@ -65,8 +64,6 @@ public class ServletUtil {
 	public static File logFile = null;
 	public static boolean swaggerInitialized = false;

-	public static final String ALTORO_COOKIE = "AltoroAccounts";
-
 	public static final String EMAIL_REGEXP = "^..*@..*\\...*$";

 	public static final String LEGAL_EMAIL_REGEXP = "^[A-Za-z0-9_\\-\\.\\+]+@[A-Za-z0-9\\-\\.]+.[A-Za-z]+$";
@@ -337,18 +334,14 @@ public class ServletUtil {
 		}
 	}

-	public static Cookie establishSession(String username, HttpSession session){
+	public static void establishSession(String username, HttpSession session){
 		try{
 			User user = DBUtil.getUserInfo(username);
 			Account[] accounts = user.getAccounts();
-		    String accountStringList = Account.toBase64List(accounts);
-		    Cookie accountCookie = new Cookie(ServletUtil.ALTORO_COOKIE, accountStringList);
 			session.setAttribute(ServletUtil.SESSION_ATTR_USER, user);
-		    return accountCookie;
 		}
 		catch(SQLException e){
 			e.printStackTrace();
-			return null;
 		}
 	}
```

### Re-test steps

Try to transfer funds that are larger than the originating account's balance and notice how the server returns an error:

![alt text](retest-images/image-9.png)

## Exploiting business logic flaw (excessive money transfer in REST API)

### Test steps

- Enter the following script while on the website (F12 > console), and observe how excessive funds (funds that are greater than 800005's balance) are sent to 800004 account:

  ```javascript
  username = 'jdoe';
  password = 'demo1234';
  res = await (
    await fetch('/altoromutual/api/login', {
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      body: JSON.stringify({
        username,
        password
      })
    })
  ).json();

  auth = res.Authorization;

  res = await (
    await fetch('/altoromutual/api/transfer', {
      headers: { 'Content-Type': 'application/json', Authorization: auth },
      method: 'POST',
      body: JSON.stringify({
        toAccount: '800004',
        fromAccount: '800005',
        transferAmount: '1000000000000'
      })
    })
  ).json();
  ```

![Sending excessive funds via REST API](test-images/image-21.png)

- Confirm that the funds are sent as in the previous vulnerability

### Cause

`OperationsUtil.doApiTransfer` does not do business logic checks before calling `DBUtil.transferFunds`.

### Fix explanation

Use the same validation in `OperationsUtil.doServletTransfer` by abstracting some of it in a common function

### Fix patch

```diff
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
index a481b6a..e914088 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
@@ -14,20 +14,54 @@ import com.ibm.security.appscan.altoromutual.model.User;

 public class OperationsUtil {

+	private static String transferAndGetMessage(String userName, long creditActId, Account debitAct, double amount) {
+		//we will not send an error immediately, but we need to have an indication when one occurs...
+		String message = null;
+		if (creditActId < 0){
+			message = "Destination account is invalid";
+		} else if (debitAct == null) {
+			message = "Originating account is invalid";
+		} else if (amount < 0){
+			message = "Transfer amount is invalid";
+		} else if (amount > debitAct.getBalance()){
+			message = "Insufficient balance in originating account";
+		}
+
+		//if transfer amount is zero then there is nothing to do
+		if (message == null && amount > 0){
+			message = DBUtil.transferFunds(userName, creditActId, debitAct.getAccountId(), amount);
+		}
+		if (message != null){
+			message = "ERROR: " + message;
+		} else {
+			message = amount + " was successfully transferred from Account " + debitAct.getAccountId() + " into Account " + creditActId + " at " + new SimpleDateFormat().format(new Date()) + ".";
+		}
+
+		return message;
+	}
+
 	public static String doApiTransfer(HttpServletRequest request, long creditActId, long debitActId,
 			double amount) {

 		try {
 			User user = OperationsUtil.getUser(request);
 			String userName = user.getUsername();
-			String message = DBUtil.transferFunds(userName, creditActId, debitActId, amount);
-			if (message != null){
-				message = "ERROR: " + message;
-			} else {
-				message = amount + " was successfully transferred from Account " + debitActId + " into Account " + creditActId + " at " + new SimpleDateFormat().format(new Date()) + ".";
+
+			Account debitAct = null;
+			try {
+				Account[] accounts = user.getAccounts();
+
+				for (Account account: accounts){
+					if (account.getAccountId() == debitActId){
+						debitAct = account;
+						break;
+					}
+				}
+			} catch (Exception e){
+				//do nothing
 			}

-			return message;
+			return transferAndGetMessage(userName, creditActId, debitAct, amount);

 		} catch (SQLException e) {
 			return "ERROR - failed to transfer funds: " + e.getLocalizedMessage();
@@ -74,30 +108,7 @@ public class OperationsUtil {
 			//do nothing
 		}

-		//we will not send an error immediately, but we need to have an indication when one occurs...
-		String message = null;
-		if (creditActId < 0){
-			message = "Destination account is invalid";
-		} else if (debitAct == null) {
-			message = "Originating account is invalid";
-		} else if (amount < 0){
-			message = "Transfer amount is invalid";
-		} else if (amount > debitAct.getBalance()){
-			message = "Insufficient balance in originating account";
-		}
-
-		//if transfer amount is zero then there is nothing to do
-		if (message == null && amount > 0){
-			message = DBUtil.transferFunds(userName, creditActId, debitAct.getAccountId(), amount);
-		}
-
-		if (message != null){
-			message = "ERROR: " + message;
-		} else {
-			message = amount + " was successfully transferred from Account " + debitAct.getAccountId() + " into Account " + creditActId + " at " + new SimpleDateFormat().format(new Date()) + ".";
-		}
-
-		return message;
+		return transferAndGetMessage(userName, creditActId, debitAct, amount);
 	}

 	public static String sendFeedback(String name, String email,
```

### Re-test steps

Run the same script in the test steps and notice how the server returns an error instead:

![alt text](retest-images/image-10.png)

## Exploiting business logic flaw (negative money transfer in REST API)

### Test steps

- Run the following script in the browser's console while on the website (F12 > console), and observe the negative funds get sent successfully:

  ```javascript
  username = 'jdoe';
  password = 'demo1234';
  res = await (
    await fetch('/altoromutual/api/login', {
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      body: JSON.stringify({
        username,
        password
      })
    })
  ).json();

  auth = res.Authorization;

  res = await (
    await fetch('/altoromutual/api/transfer', {
      headers: { 'Content-Type': 'application/json', Authorization: auth },
      method: 'POST',
      body: JSON.stringify({
        toAccount: '800005',
        fromAccount: '800004',
        transferAmount: '-2000000'
      })
    })
  ).json();
  ```

![Transferring negative funds](test-images/image-22.png)

- Confirm the new balances as in the previous vulnerability

### Cause

`OperationsUtil.doApiTransfer` does not do business logic checks before calling `DBUtil.transferFunds`.

### Fix explanation

Fixed in the previous vulnerability by abstracting the business logic checking code in a common function that is called by both `OperationsUtil.doServletTransfer` and `OperationsUtil.doApiTransfer`.

### Fix patch

Fixed in the previous vulnerability by abstracting the business logic checking code in a common function that is called by both `OperationsUtil.doServletTransfer` and `OperationsUtil.doApiTransfer`.

### Re-test steps

Run the same script in the test steps and notice how the server returns an error instead:

![alt text](retest-images/image-11.png)

## Bypassing access control (sending money from a foreign account in the REST API)

### Test steps

- Run the following script in your browser's dev tools' console while on the website (F12 > console), and observe how funds get sent from 800000 to 800004 although 800000 does not belong to the sending user:

  ```javascript
  username = 'jdoe';
  password = 'demo1234';
  res = await (
    await fetch('/altoromutual/api/login', {
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      body: JSON.stringify({
        username,
        password
      })
    })
  ).json();

  auth = res.Authorization;

  res = await (
    await fetch('/altoromutual/api/transfer', {
      headers: { 'Content-Type': 'application/json', Authorization: auth },
      method: 'POST',
      body: JSON.stringify({
        fromAccount: '800000',
        toAccount: '800004',
        transferAmount: '2000000'
      })
    })
  ).json();
  ```

![Transferring money from a foreign account](test-images/image-23.png)

- Confirm the new balances as in the previous vulnerability

### Cause

`OperationsUtil.doApiTransfer` does not do business logic checks before calling `DBUtil.transferFunds`.

### Fix explanation

Fixed in the previous vulnerability by abstracting the business logic checking code in a common function that is called by both `OperationsUtil.doServletTransfer` and `OperationsUtil.doApiTransfer`.

### Fix patch

Fixed in the previous vulnerability by abstracting the business logic checking code in a common function that is called by both `OperationsUtil.doServletTransfer` and `OperationsUtil.doApiTransfer`.

### Re-test steps

Run the same script in the test steps and notice how the server returns an error instead:

![alt text](retest-images/image-12.png)

## Bypassing access control (sending money from a foreign account through cookie manipulation)

### Test steps

- Login with Jane Doe's account (jdoe, demo1234)

- Go to `My Account` > `Transfer Funds`:

![My Account > Transfer Funds](test-images/image-24.png)

- Run the following javascript code in the browser console while on the page (F12 > console) to add the victim's account to your `AltoroAccounts` cookie:

  ```javascript
  evilCookie = btoa('800000~evil~101|800004~Savings~101');
  document.cookie = `AltoroAccounts=${evilCookie}`;
  opt = document.createElement('option');
  opt.value = '800000';
  opt.innerHTML = '800000 victim';
  fromAccount.appendChild(opt);
  ```

![Adding an evil cookie](test-images/image-25.png)

- Choose "800000 victim" from the "from" dropdown list (notice that it does not belong to Jane Doe), choose one of your accounts from the "to" drop down list and enter an amount of money:

![Transferring money from the victim](test-images/image-26.png)

- Click `Transfer Money` and notice how the operation is successful:

![Transferring money from the victim successful](test-images/image-27.png)

### Cause

`OperationsUtil.doServletTransfer()` checks for a cookie called `AltoroAccounts`, and if it exists, it uses it to determine the user's accounts. This cookie can be modified on the client side.

### Fix explanation

Fixed while fixing the excessive money transfer (normal API) vulnerability since we removed the code that treats cookies as a source of truth of the user's accounts.

### Fix patch

Fixed while fixing the excessive money transfer (normal API) vulnerability since we removed the code that treats cookies as a source of truth of the user's accounts.

### Re-test steps

Do the same test steps above and observe how the server returns an error instead:

![alt text](retest-images/image-13.png)

## Bypassing access control (viewing a foreign account details)

### Test steps

- Go to "View Account Summary" > "Go" (on any account)

![Account details](test-images/image-30.png)

- Change the `listAccounts` URL parameter to a bank account number of another user, and observe how their account details are returned

![Foreign account details](test-images/image-31.png)

### Cause

`balance.jsp` does not check if the account id belongs to the logged in user and the database does not filter the accounts based on the logged in user

### Fix explanation

In `balance.jsp`, if the requested account is not an account of the user, show the details of the user's first account instead. Moreover, change `DBUtil.getAccount()` and its usages to take the username of the target user and filter the queried data accordingly (this will fix multiple other vulnerabilities below).

### Fix patch

```diff
diff --git a/src/WebContent/bank/balance.jsp b/src/WebContent/bank/balance.jsp
index 6314d98..99543ac 100644
--- a/src/WebContent/bank/balance.jsp
+++ b/src/WebContent/bank/balance.jsp
@@ -39,16 +39,24 @@ IBM AltoroJ
 					ArrayList<Account> accounts = new ArrayList<Account>();
 					java.lang.String paramName = request.getParameter("acctId");
 					String accountName = paramName;
+					boolean found = false;
+					Account[] userAccounts = user.getAccounts();

-					for (Account account: user.getAccounts()){
+					for (Account account: userAccounts){

 						if (!String.valueOf(account.getAccountId()).equals(paramName))
 							accounts.add(account);
 						else {
+							found = true;
 							accounts.add(0, account);
 							accountName = account.getAccountId() + " " + account.getAccountName();
 						}
 					}
+
+					if (!found) {
+						paramName = String.valueOf(userAccounts[0].getAccountId());
+						accountName = paramName;
+					}
 				%>

 		<!-- To modify account information do not connect to SQL source directly.  Make all changes
```

Changing `DBUtil.getAccount()`:

```diff
diff --git a/src/WebContent/bank/balance.jsp b/src/WebContent/bank/balance.jsp
index 99543ac..8354fe5 100644
--- a/src/WebContent/bank/balance.jsp
+++ b/src/WebContent/bank/balance.jsp
@@ -79,7 +79,7 @@ IBM AltoroJ
 								for (Account account: accounts){
 									out.println("<option value=\""+account.getAccountId()+"\">" + account.getAccountId() + " " + account.getAccountName() + "</option>");
 								}
-								double dblBalance = Account.getAccount(paramName).getBalance();
+								double dblBalance = Account.getAccount(paramName, user.getUsername()).getBalance();
 								String format = (dblBalance<1)?"$0.00":"$.00";
 								String balance = new DecimalFormat(format).format(dblBalance);
 							%>
@@ -109,7 +109,7 @@ IBM AltoroJ
 		    <td>
 		      <br><b>10 Most Recent Transactions</b><table border=1 cellpadding=2 cellspacing=0 width='590'><tr><th bgcolor=#cccccc width=100>Date </th><th width=290>Description</th><th width=100>Amount</th></tr></table><DIV ID='recent' STYLE='overflow: hidden; overflow-y: scroll; width:590px; height: 152px; padding:0px; margin: 0px' ><table border=1 cellpadding=2 cellspacing=0 width='574'>
 		      <%
-		      Transaction[] transactions = DBUtil.getTransactions(null, null, new Account[]{DBUtil.getAccount(Long.valueOf(paramName))}, 10);
+		      Transaction[] transactions = DBUtil.getTransactions(null, null, new Account[]{Account.getAccount(paramName, user.getUsername())}, 10);
 				for (Transaction transaction: transactions){
 			   		double dblAmt = transaction.getAmount();
 					String dollarFormat = (dblAmt<1)?"$0.00":"$.00";
diff --git a/src/src/com/ibm/security/appscan/altoromutual/api/AccountAPI.java b/src/src/com/ibm/security/appscan/altoromutual/api/AccountAPI.java
index d313e64..f33f05a 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/api/AccountAPI.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/api/AccountAPI.java
@@ -59,11 +59,12 @@ public class AccountAPI extends AltoroAPI {
 		// Check that the user is logged in
 		// System.out.println(accountNo);
 		String response;
+		String userName = OperationsUtil.getUserName(request);

 		// not checking the account number, side privilege escalation possible
 		try {
 			// Get the account balance
-			double dblBalance = Account.getAccount(accountNo).getBalance();
+			double dblBalance = Account.getAccount(accountNo, userName).getBalance();
 			String format = (dblBalance < 1) ? "$0.00" : "$.00";
 			String balance = new DecimalFormat(format).format(dblBalance);
 			response = "{\"balance\" : \"" + balance + "\" ,\n";
@@ -73,13 +74,13 @@ public class AccountAPI extends AltoroAPI {
 		} catch (Exception e) {
 			return Response
 					.status(Response.Status.INTERNAL_SERVER_ERROR)
-					.entity("{Error : " + e.getLocalizedMessage())
+					.entity("{Error : " + e.getLocalizedMessage() + "}")
 					.build();
 		}

 		// Get the last 10 transactions
 		String last10Transactions;
-		last10Transactions = this.getLastTenTransactions(accountNo);
+		last10Transactions = this.getLastTenTransactions(userName, accountNo);
 		if (last10Transactions.equals("Error")) {
 			return Response
 					.status(Response.Status.INTERNAL_SERVER_ERROR)
@@ -116,7 +117,7 @@ public class AccountAPI extends AltoroAPI {
 		response = "{";
 		// Get the last 10 transactions
 		String last10Transactions;
-		last10Transactions = this.getLastTenTransactions(accountNo);
+		last10Transactions = this.getLastTenTransactions(OperationsUtil.getUserName(request), accountNo);
 		if (last10Transactions.equals("Error")) {
 			return Response
 					.status(Response.Status.INTERNAL_SERVER_ERROR)
@@ -166,10 +167,9 @@ public class AccountAPI extends AltoroAPI {

 		try {
 			Account[] account = new Account[1];
-			account[0] = user.lookupAccount(Long.parseLong(accountNo));
+			account[0] = Account.getAccount(accountNo, user.getUsername());

-			transactions = user.getUserTransactions(startString, endString,
-					account);
+			transactions = user.getUserTransactions(startString, endString, account);
 		} catch (SQLException e) {
 			return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
 					.entity("{Error : Database failed to return requested data} " + e.getLocalizedMessage())
@@ -207,13 +207,11 @@ public class AccountAPI extends AltoroAPI {
 	}

 	// utilities for the API
-	private String getLastTenTransactions(String accountNo) {
+	private String getLastTenTransactions(String userName, String accountNo) {
 		String response = "";
 		try {
 			response = response + "\"last_10_transactions\" :\n[";
-			Transaction[] transactions = DBUtil
-					.getTransactions(null, null, new Account[] { DBUtil
-							.getAccount(Long.valueOf(accountNo)) }, 10);
+			Transaction[] transactions = DBUtil.getTransactions(null, null, new Account[] { Account.getAccount(accountNo, userName) }, 10);
 			for (Transaction transaction : transactions) {
 				double dblAmt = transaction.getAmount();
 				String dollarFormat = (dblAmt < 1) ? "$0.00" : "$.00";
diff --git a/src/src/com/ibm/security/appscan/altoromutual/model/Account.java b/src/src/com/ibm/security/appscan/altoromutual/model/Account.java
index 03087dd..6f48258 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/model/Account.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/model/Account.java
@@ -34,17 +34,13 @@ public class Account {
 	private String accountName = null;
 	private double balance = -1;

-	public static Account getAccount(String accountNo) throws SQLException {
+	public static Account getAccount(String accountNo, String username) throws SQLException {
 		if (accountNo == null || accountNo.trim().length() == 0)
 			return null;

 		long account = Long.parseLong(accountNo);

-		return getAccount(account);
-	}
-
-	public static Account getAccount(long account) throws SQLException {
-		return DBUtil.getAccount(account);
+		return DBUtil.getAccount(account, username);
 	}

 	public Account(long accountId, String accountName, double balance) {
diff --git a/src/src/com/ibm/security/appscan/altoromutual/model/User.java b/src/src/com/ibm/security/appscan/altoromutual/model/User.java
index e59ae65..a9a0542 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/model/User.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/model/User.java
@@ -82,14 +82,6 @@ public class User implements java.io.Serializable{
 		}
 	}

-	public Account lookupAccount(Long accountNumber) {
-		for (Account account : getAccounts()) {
-			if (account.getAccountId() == accountNumber)
-				return account;
-		}
-		return null;
-	}
-
 	public long getCreditCardNumber(){
 		for (Account account: getAccounts()){
 			if (DBUtil.CREDIT_CARD_ACCOUNT_NAME.equals(account.getAccountName()))
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
index aa3bd9d..a7bfadc 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/DBUtil.java
@@ -309,8 +309,8 @@ public class DBUtil {
 			Connection connection = getConnection();
 			Statement statement = connection.createStatement();

-			Account debitAccount = Account.getAccount(debitActId);
-			Account creditAccount = Account.getAccount(creditActId);
+			Account debitAccount = getAccount(debitActId, username);
+			Account creditAccount = getAccount(creditActId, null);

 			if (debitAccount == null){
 				return "Originating account is invalid";
@@ -458,19 +458,32 @@ public class DBUtil {
 		}
 	}

-	public static Account getAccount(long accountNo) throws SQLException {
+	public static Account getAccount(long accountNo, String userName) throws SQLException {

 		Connection connection = getConnection();
-		Statement statement = connection.createStatement();
-		ResultSet resultSet =statement.executeQuery("SELECT ACCOUNT_NAME, BALANCE FROM ACCOUNTS WHERE ACCOUNT_ID = "+ accountNo +" "); /* BAD - user input should always be sanitized */
+		StringBuffer query = new StringBuffer();
+		query.append("SELECT ACCOUNT_NAME, BALANCE FROM ACCOUNTS WHERE ACCOUNT_ID = ?");
+
+		if (userName != null) {
+			query.append(" AND USERID = ?");
+		}

 		ArrayList<Account> accounts = new ArrayList<Account>(3);
-		while (resultSet.next()){
-			String name = resultSet.getString("ACCOUNT_NAME");
-			double balance = resultSet.getDouble("BALANCE");
-			Account newAccount = new Account(accountNo, name, balance);
-			accounts.add(newAccount);
+
+		try (PreparedStatement statement = connection.prepareStatement(query.toString())) {
+			statement.setString(1, String.valueOf(accountNo));
+			if (userName != null) {
+				statement.setString(2, userName);
+			}
+			ResultSet resultSet = statement.executeQuery();
+			while (resultSet.next()){
+				String name = resultSet.getString("ACCOUNT_NAME");
+				double balance = resultSet.getDouble("BALANCE");
+				Account newAccount = new Account(accountNo, name, balance);
+				accounts.add(newAccount);
+			}
 		}
+

 		if (accounts.size()==0)
 			return null;
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
index e914088..411b844 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/OperationsUtil.java
@@ -49,14 +49,7 @@ public class OperationsUtil {

 			Account debitAct = null;
 			try {
-				Account[] accounts = user.getAccounts();
-
-				for (Account account: accounts){
-					if (account.getAccountId() == debitActId){
-						debitAct = account;
-						break;
-					}
-				}
+				debitAct = DBUtil.getAccount(debitActId, userName);
 			} catch (Exception e){
 				//do nothing
 			}
@@ -89,12 +82,7 @@ public class OperationsUtil {
 			}

 			if (accountId > 0) {
-				for (Account account: accounts){
-					if (account.getAccountId() == accountId){
-						debitAct = account;
-						break;
-					}
-				}
+				debitAct = DBUtil.getAccount(accountId, userName);
 			} else {
 				for (Account account: accounts){
 					if (account.getAccountName().equalsIgnoreCase(accountIdString)){
@@ -125,17 +113,19 @@ public class OperationsUtil {

 		return null;
 	}
-
-	public static User getUser(HttpServletRequest request) throws SQLException{
-
+
+	public static String getUserName(HttpServletRequest request) {
 		String accessToken = request.getHeader("Authorization").replaceAll("Bearer ", "");

 		//Get username password and date
 		String decodedToken = new String(Base64.decodeBase64(accessToken));
 		StringTokenizer tokenizer = new StringTokenizer(decodedToken,":");
 		String username = new String(Base64.decodeBase64(tokenizer.nextToken()));
-		return DBUtil.getUserInfo(username);
-
+		return username;
+	}
+
+	public static User getUser(HttpServletRequest request) throws SQLException{
+		return DBUtil.getUserInfo(getUserName(request));
 	}

 	public static String makeRandomString() {
```

### Re-test steps

Do the same test steps, and observe how the server returns the details of the user's first account instead of the victim's account:

![alt text](retest-images/image-14.png)

## Bypassing access control (getting a foreign account details through the REST API)

### Test steps

Run the following script in your browser's dev tools' console while on the website (F12 > console), and observe how you can get the details of the 800000 account which does not belong to `jdoe`:

```javascript
username = 'jdoe';
password = 'demo1234';
res = await (
  await fetch('/altoromutual/api/login', {
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
    body: JSON.stringify({
      username,
      password
    })
  })
).json();

auth = res.Authorization;

res = await (
  await fetch('/altoromutual/api/account/800000', {
    headers: { 'Content-Type': 'application/json', Authorization: auth },
    method: 'GET'
  })
).json();
```

![Getting a foreign account details](test-images/image-28.png)

### Cause

`AccountAPI.getAccountBalance()` does not check whether the account in the parameter belongs to the user and the database does not filter the accounts based on the user

### Fix explanation

Fixed while fixing the previous vulnerability.

### Fix patch

Fixed while fixing the previous vulnerability.

### Re-test steps

Run the same script in the test steps and notice how the server returns an error instead:

![alt text](retest-images/image-15.png)

## Bypassing access control (getting the last ten transactions of a foreign account through the REST API)

### Test steps

Run the following script in your browser's dev tools' console while on the website (F12 > console), and observe how you can get the last ten transactions of the 800002 account which does not belong to `jdoe`:

```javascript
username = 'jdoe';
password = 'demo1234';
res = await (
  await fetch('/altoromutual/api/login', {
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
    body: JSON.stringify({
      username,
      password
    })
  })
).json();

auth = res.Authorization;

res = await (
  await fetch('/altoromutual/api/account/800002/transactions', {
    headers: { 'Content-Type': 'application/json', Authorization: auth },
    method: 'GET'
  })
).json();
```

![Getting foreign last ten transactions](test-images/image-29.png)

### Cause

`AccountAPI.showLastTenTransactions()` does not check whether the account in the parameter belongs to the user and the database does not filter the transactions based on the user

### Fix explanation

Fixed while fixing the previous vulnerabilities.

### Fix patch

Fixed while fixing the previous vulnerabilities.

### Re-test steps

Run the same script in the test steps and notice how the server returns an error instead:

![alt text](retest-images/image-16.png)

## Bypassing access control (accessing admin pages)

### Test steps

- Log in as a non-admin user

![Logging in as a normal user](test-images/image-32.png)

- Visit /admin/admin.jsp and observe how the user can access admin pages

![Accessing admin pages](test-images/image-33.png)

### Cause

The admin URL pattern in `AdminFilter` in `web.xml` is misspelled (`/adimn/*` instead of `/admin/*`)

### Fix explanation

Correct the "adimn" typo in `web.xml`.

### Fix patch

```diff
diff --git a/src/WebContent/WEB-INF/web.xml b/src/WebContent/WEB-INF/web.xml
index b5d02e5..f0d7940 100644
--- a/src/WebContent/WEB-INF/web.xml
+++ b/src/WebContent/WEB-INF/web.xml
@@ -43,7 +43,7 @@
   </filter-mapping>
   <filter-mapping>
     <filter-name>AdminFilter</filter-name>
-    <url-pattern>/adimn/*</url-pattern>
+    <url-pattern>/admin/*</url-pattern>
     <dispatcher>FORWARD</dispatcher>
     <dispatcher>INCLUDE</dispatcher>
     <dispatcher>REQUEST</dispatcher>
```

### Re-test steps

Visit `/admin/admin.jsp` as an unauthorized user and notice how you are redirected back to your homepage:

![alt text](retest-images/image-17.png)

## Cross site scripting in `/bank/customize.jsp`

### Test steps

- Log in as any user (you will be the victim)

- Visit <http://base_url/bank/customize.jsp?lang=%3Cbr%3E%3Cform%3E%3Clabel%3Eevil%20username%3C/label%3E%3Cinput%20type=%27text%27%3E%3Cbr%3E%3Clabel%3Eevil%20password%3C/label%3E%3Cinput%20type=%27password%27%3E%3Cinput%20type=%27submit%27%3E%3C/form%3E> and observe how an evil form was injected:

![XSS in customize.jsp](test-images/image-34.png)

### Cause

`customize.jsp` does not sanitize the request parameter before placing it on the DOM

### Fix explanation

Use the function `ServletUtil.sanitizeWeb` to sanitize the request parameter before placing it on the DOM

### Fix patch

```diff
diff --git a/src/WebContent/bank/customize.jsp b/src/WebContent/bank/customize.jsp
index 66c815c..99f56e1 100644
--- a/src/WebContent/bank/customize.jsp
+++ b/src/WebContent/bank/customize.jsp
@@ -20,6 +20,7 @@ IBM AltoroJ
 (c) Copyright IBM Corp. 2008, 2013 All Rights Reserved.
 */
 %>
+<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil" errorPage="notfound.jsp"%>

 <jsp:include page="/header.jspf"/>

@@ -41,7 +42,7 @@ IBM AltoroJ

 		<form method="post">
 		  <p>
-		  Current Language: <%=(request.getParameter("lang")==null)?"":request.getParameter("lang")%>
+		  Current Language: <%=(request.getParameter("lang")==null)?"":ServletUtil.sanitizeWeb(request.getParameter("lang"))%>
 		  </p>

 		  <p>
```

### Re-test steps

Follow the same test steps and observe the HTML code appears as normal text instead of being injected:

![alt text](retest-images/image-18.png)

## Cross site scripting in `/search.jsp`

### Test steps

You are the victim, visit <http://base_url/search.jsp?query=%3Cform%3E%3Clabel%3Eevil+username%3C%2Flabel%3E%3Cinput+type%3D%22text%22%3E%3Cbr%3E%3Clabel%3Eevil+password%3C%2Flabel%3E%3Cinput+type%3D%22password%22%3E%3C%2Fform%3E> and observe how an evil form was injected:

![XSS in search.jsp](test-images/image-35.png)

### Cause

`search.jsp` does not sanitize the request parameter before placing it on the DOM

### Fix explanation

Use the function `ServletUtil.sanitizeWeb` to sanitize the request parameter before placing it on the DOM

### Fix patch

```diff
diff --git a/src/WebContent/search.jsp b/src/WebContent/search.jsp
index cccd7ae..47eb9b5 100644
--- a/src/WebContent/search.jsp
+++ b/src/WebContent/search.jsp
@@ -41,7 +41,7 @@ IBM AltoroJ

 		<p>No results were found for the query:<br /><br />

-		<%= query %>
+		<%= ServletUtil.sanitizeWeb(query) %>

 		</div>
     </td>
```

### Re-test steps

Follow the same test steps and observe the HTML code appears as normal text instead of being injected:

![alt text](retest-images/image-19.png)

## Cross site scripting in `/util/serverStatusCheckService.jsp`

### Test steps

- You are the victim, visit <http://base_url/util/serverStatusCheckService.jsp?HostName=%3Cscript%3Ealert(%22XSS%20injected%22)%3C/script%3E> and observe how an arbitrary script is run

![XSS in serverStatusCheckService.jsp](test-images/image-36.png)

### Cause

`serverStatusCheckService.jsp` does not sanitize the request parameter before placing it on the DOM

### Fix explanation

Use the function `ServletUtil.sanitizeWeb` to sanitize the request parameter before placing it on the DOM

### Fix patch

```diff
diff --git a/src/WebContent/util/serverStatusCheckService.jsp b/src/WebContent/util/serverStatusCheckService.jsp
index 2737276..5263c79 100644
--- a/src/WebContent/util/serverStatusCheckService.jsp
+++ b/src/WebContent/util/serverStatusCheckService.jsp
@@ -1,6 +1,7 @@
 <%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
+<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil" errorPage="notfound.jsp"%>

 {
-	"HostName": "<%=request.getParameter("HostName")%>",
+	"HostName": "<%=ServletUtil.sanitizeWeb(request.getParameter("HostName"))%>",
 	"HostStatus": "OK"
 }
\ No newline at end of file
```

### Re-test steps

Follow the same test steps and observe the HTML code appears as normal text instead of being injected:

![alt text](retest-images/image-20.png)

## Cross site scripting in `/bank/queryxpath.jsp`

### Test steps

- Log in as any user (you will be the victim)

- Visit <http://base_url/bank/queryxpath.jsp?content=queryxpath.jsp&query=%22/%3E%3Cscript%3Ealert(%27xss%20injected%27)%3C/script%3E> and observe how an arbitrary script is run

![XSS in queryxpath.jsp](test-images/image-37.png)

### Cause

`queryxpath.jsp` does not sanitize the request parameter before placing it on the DOM

### Fix explanation

Use the function `ServletUtil.sanitizeWeb` to sanitize the request parameter before placing it on the DOM

### Fix patch

```diff
diff --git a/src/WebContent/bank/queryxpath.jsp b/src/WebContent/bank/queryxpath.jsp
index cdc88dd..4191017 100644
--- a/src/WebContent/bank/queryxpath.jsp
+++ b/src/WebContent/bank/queryxpath.jsp
@@ -33,7 +33,7 @@ IBM AltoroJ
 			  Search our news articles database
 			  <br /><br />
 				<input type="hidden" id=content" name="content" value="queryxpath.jsp"/>
-				<input type="text" id="query" name="query" width=450 value="<%=(request.getParameter("query")==null)?"Enter title (e.g. Watchfire)":request.getParameter("query")%>"/>
+				<input type="text" id="query" name="query" width=450 value="<%=(request.getParameter("query")==null)?"Enter title (e.g. Watchfire)":ServletUtil.sanitizeWeb(request.getParameter("query"))%>"/>
 				<input type="submit" width=75 id="Button1" value="Query">
 			  <br /><br />
 			<%
```

### Re-test steps

Follow the same test steps and observe the HTML code appears as normal text instead of being injected:

![alt text](retest-images/image-21.png)

## Cross site scripting in `/bank/transaction.jsp`

### Test steps

- Log in as any user (you will be the victim)

- Visit <http://base_url/bank/transaction.jsp?startDate=%22/%3E%3Cscript%3Ealert(%22XSS%20injected%22)%3C/script%3E> and observe how an arbitrary script is run

![XSS in transaction.jsp](test-images/image-39.png)

### Cause

`transaction.jsp` does not sanitize the request parameters before placing them on the DOM

### Fix explanation

Use the function `ServletUtil.sanitizeWeb` to sanitize the request parameter before placing it on the DOM

### Fix patch

```diff
diff --git a/src/WebContent/bank/transaction.jsp b/src/WebContent/bank/transaction.jsp
index dc58e30..48f802b 100644
--- a/src/WebContent/bank/transaction.jsp
+++ b/src/WebContent/bank/transaction.jsp
@@ -32,6 +32,8 @@ IBM AltoroJ

 		<%@page import="java.util.Date"%>
 		<%@page import="com.ibm.security.appscan.altoromutual.model.Transaction"%>
+		<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil" errorPage="notfound.jsp"%>
+

 		<div class="fl" style="width: 99%;">

@@ -123,9 +125,9 @@ IBM AltoroJ
 		<table border="0" style="padding-bottom:10px;">
 		    <tr>
 		        <td valign=top>After</td>
-		        <td><input id="startDate" name="startDate" type="text" value="<%=(request.getParameter("startDate")==null)?"":request.getParameter("startDate")%>"/><br /><span class="credit">yyyy-mm-dd</span></td>
+		        <td><input id="startDate" name="startDate" type="text" value="<%=(request.getParameter("startDate")==null)?"":ServletUtil.sanitizeWeb(request.getParameter("startDate"))%>"/><br /><span class="credit">yyyy-mm-dd</span></td>
 		        <td valign=top>Before</td>
-		        <td><input name="endDate" id="endDate" type="text" value="<%=(request.getParameter("endDate")==null)?"":request.getParameter("endDate") %>"/><br /><span class="credit">yyyy-mm-dd</span></td>
+		        <td><input name="endDate" id="endDate" type="text" value="<%=(request.getParameter("endDate")==null)?"":ServletUtil.sanitizeWeb(request.getParameter("endDate")) %>"/><br /><span class="credit">yyyy-mm-dd</span></td>
 		        <td valign=top><input type=submit value=Submit /></td>
 		    </tr>
 		</table>
```

### Re-test steps

- Follow the same test steps and observe the HTML code appears as normal text instead of being injected:

![alt text](retest-images/image-22.png)

- Change the `startDate` parameter to `endDate` and observe how there is still no injection:

![alt text](retest-images/image-23.png)

## Cross site scripting in `/bank/feedbacksuccess.jsp`

### Test steps

You are the victim, visit <http://base_url/feedbacksuccess.jsp?email_addr=%3Cform%20method=%22POST%22%20action=%22/test%22%3E%3Clabel%3EEvil%20username%3C/label%3E%3Cinput%20type=%22text%22%3E%3Cbr%3E%3Clabel%3EEvil%20password%3C/label%3E%3Cinput%20type=%22password%22%3E%3Cbr%3E%3Cinput%20type=%22submit%22%3E> and observe how an evil form is injected:

![XSS in feedbacksuccess.jsp](test-images/image-40.png)

### Cause

The `ServerUtil.sanitzieHtmlWithRegex` method that `feedbacksuccess.jsp` uses does not exhaustively sanitize the request parameter before placing it on the DOM

### Fix explanation

Replace usages of `ServerUtil.sanitzieHtmlWithRegex` with `ServerUtil.sanitizeWeb`

### Fix patch

```diff
diff --git a/src/WebContent/feedbacksuccess.jsp b/src/WebContent/feedbacksuccess.jsp
index 0b53b24..44dd5d0 100644
--- a/src/WebContent/feedbacksuccess.jsp
+++ b/src/WebContent/feedbacksuccess.jsp
@@ -43,9 +43,9 @@ IBM AltoroJ
 		 <% String email = (String) request.getParameter("email_addr");
 		 	boolean regExMatch = email!=null && email.matches(ServletUtil.EMAIL_REGEXP);
 		 	if (email != null && email.trim().length() != 0 && regExMatch) {%>
-			 Our reply will be sent to your email: <%= ServletUtil.sanitzieHtmlWithRegex(email.toLowerCase())/*ServletUtil.sanitizeWeb(email.toLowerCase())*/%>
+			 Our reply will be sent to your email: <%=ServletUtil.sanitizeWeb(email.toLowerCase())%>
 		<% } else {%>
-			However, the email you gave is incorrect (<%=ServletUtil.sanitzieHtmlWithRegex(email.toLowerCase()) /*ServletUtil.sanitizeWeb(email.toLowerCase())*/%>) and you will not receive a response.
+			However, the email you gave is incorrect (<%=ServletUtil.sanitizeWeb(email.toLowerCase())%>) and you will not receive a response.
 		<% }%>
 		</p>
 		<% if (ServletUtil.isAppPropertyTrue("enableFeedbackRetention")){%>
diff --git a/src/WebContent/index.jsp b/src/WebContent/index.jsp
index a00e710..a067d02 100644
--- a/src/WebContent/index.jsp
+++ b/src/WebContent/index.jsp
@@ -92,7 +92,7 @@ IBM AltoroJ
 				%>
 				<%=text %>
 			<%  } catch (Exception e) { %>
-				<p>Failed due to <%= ServletUtil.sanitzieHtmlWithRegex(e.getLocalizedMessage()) %></p>
+				<p>Failed due to <%= ServletUtil.sanitizeWeb(e.getLocalizedMessage()) %></p>
 	 		<% } %>
 		<%
 		} else {
@@ -108,7 +108,7 @@ IBM AltoroJ
 		<%  try { %>
 			<jsp:include page="<%= content %>"/>
 		<%  } catch (Exception e) { %>
-			<p>Failed due to <%= ServletUtil.sanitzieHtmlWithRegex(e.getLocalizedMessage()) %></p>
+			<p>Failed due to <%= ServletUtil.sanitizeWeb(e.getLocalizedMessage()) %></p>
  		<% }
 		}%>
     </td>
diff --git a/src/src/com/ibm/security/appscan/altoromutual/util/ServletUtil.java b/src/src/com/ibm/security/appscan/altoromutual/util/ServletUtil.java
index 81fb326..c1833fc 100644
--- a/src/src/com/ibm/security/appscan/altoromutual/util/ServletUtil.java
+++ b/src/src/com/ibm/security/appscan/altoromutual/util/ServletUtil.java
@@ -243,13 +243,6 @@ public class ServletUtil {
 		return StringEscapeUtils.escapeHtml(data);
 	}

-	public static String sanitzieHtmlWithRegex(String input) {
-		if (XSS_REGEXP.matcher(input).matches()) {
-			return "";
-		}
-		return input;
-	}
-
 	/* initializes AltoroJ demo properties table */
 	public static void initializeAppProperties(ServletContext servletContext) {
```

### Re-test steps

Follow the same test steps and observe the HTML code appears as normal text instead of being injected:

![alt text](retest-images/image-24.png)

## Unvalidated redirect in `/bank/customize.jsp`

### Test steps

- Log in as any user (you will be the victim)

- Visit `/bank/customize.jsp?content=https://www.google.com` and observe how you are redirected to `https://www.google.com` without warning.

![Unvalidated redirect in customize.jsp](test-images/image-41.png)

### Cause

`customize.jsp` sends a redirect header to whatever is in the `content` request parameter

### Fix explanation

Redirect to the disclaimer page that shows the user that he is about to be redirected off the website instead of redirecting them directly

### Fix patch

```diff
diff --git a/src/WebContent/bank/customize.jsp b/src/WebContent/bank/customize.jsp
index 99f56e1..d1c9e0f 100644
--- a/src/WebContent/bank/customize.jsp
+++ b/src/WebContent/bank/customize.jsp
@@ -33,7 +33,7 @@ IBM AltoroJ
 			String content = request.getParameter("content");
 			if (content != null && !content.equalsIgnoreCase("customize.jsp")){
 				if (content.startsWith("http://") || content.startsWith("https://")){
-					response.sendRedirect(content);
+					response.sendRedirect(request.getContextPath() + "/disclaimer.htm?url=" + content);
 				}
 			}
 		%>
```

### Re-test steps

Follow the same test steps and observe how you are redirected to the disclaimer page instead:

![alt text](retest-images/image-25.png)

## Additional patches

Improvements to the previous patches:

### Remove error page from imports in jsps

```diff
diff --git a/src/WebContent/bank/customize.jsp b/src/WebContent/bank/customize.jsp
index d1c9e0f..865991a 100644
--- a/src/WebContent/bank/customize.jsp
+++ b/src/WebContent/bank/customize.jsp
@@ -20,7 +20,7 @@ IBM AltoroJ
 (c) Copyright IBM Corp. 2008, 2013 All Rights Reserved.
 */
 %>
-<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil" errorPage="notfound.jsp"%>
+<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil"%>

 <jsp:include page="/header.jspf"/>

diff --git a/src/WebContent/bank/transaction.jsp b/src/WebContent/bank/transaction.jsp
index 48f802b..d5a5e40 100644
--- a/src/WebContent/bank/transaction.jsp
+++ b/src/WebContent/bank/transaction.jsp
@@ -32,7 +32,7 @@ IBM AltoroJ

 		<%@page import="java.util.Date"%>
 		<%@page import="com.ibm.security.appscan.altoromutual.model.Transaction"%>
-		<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil" errorPage="notfound.jsp"%>
+		<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil"%>


 		<div class="fl" style="width: 99%;">
diff --git a/src/WebContent/util/serverStatusCheckService.jsp b/src/WebContent/util/serverStatusCheckService.jsp
index 5263c79..e86e34a 100644
--- a/src/WebContent/util/serverStatusCheckService.jsp
+++ b/src/WebContent/util/serverStatusCheckService.jsp
@@ -1,5 +1,5 @@
 <%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
-<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil" errorPage="notfound.jsp"%>
+<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil"%>

 {
 	"HostName": "<%=ServletUtil.sanitizeWeb(request.getParameter("HostName"))%>",
```

### Remove debugging message

```diff
diff --git a/src/WebContent/index.jsp b/src/WebContent/index.jsp
index a067d02..baf1e15 100644
--- a/src/WebContent/index.jsp
+++ b/src/WebContent/index.jsp
@@ -98,7 +98,6 @@ IBM AltoroJ
 		} else {
 			String basePath = "static";
 			Path resolved = Paths.get(basePath).resolve(content).normalize();
-			System.out.println(resolved);
 			if (resolved.startsWith(basePath))
 				content = resolved.toString();
 			else
```
