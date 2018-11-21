# eZ Publish Legacy User Form Token extension


This extension aims to stop CSRF attacks against eZ Publish 
implementing the easiest remediation described in [detectify](https://support.detectify.com/customer/portal/articles/1969819-login-csrf).

It works like the official extension eZ Form Token adding input & output filter events, 
which verify that POST requests have an input matching with a generated custom cookie.
The difference with eZ Form Token is that the verification is done on requests made by the anonymous user.

This is all done transparently for html/xhtml forms, but requires changes to all ajax POST code.
If the form token does not verify, an exception is currently thrown and an
error 500 is send to the HTTP client.

It is possible to configure modules to be protected and the cookie parameter in the new configuration block ```[UserFormToken]``` in site.ini
(see defaults in settings/site.ini.append.php file of this extension)

See also:
[How to protect against login CSRF? in stackexchange](https://security.stackexchange.com/questions/59411/how-to-protect-against-login-csrf)
