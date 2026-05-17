# AdaptXSS PHP Fallback Receiver

A minimal PHP 8.0+ endpoint that receives XSS detection events when Node.js is unavailable.

## Setup

```bash
# Ensure the store directory is writable by the web server
chmod 775 store/
# or (permissive for dev):
chmod 777 store/

# Start the built-in PHP dev server
php -S localhost:8080
```

## Test

```bash
curl -X POST http://localhost:8080/receiver.php \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"sess_test_123","label":"malicious","probability":0.92,
       "features":[1,1,1,1,0,0,0.5,0.7],"timestamp":1716000000000,"latencyMs":3.2}'
# Expected: {"ok":true}
```

Events are written to `store/events.json` as newline-delimited JSON (one event per line).

## Update reporter endpoint

In your `AdaptXSSObserver`:
```js
const monitor = new AdaptXSS.AdaptXSSObserver({
  reportUrl: 'http://localhost:8080/receiver.php'
});
```
