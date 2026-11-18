# VulnScope XSS lab add-on

Unzip and copy `app/xss_lab.py`, `app/templates/xss_lab.html`, `app/static/xss_lab.css`, and `scanner/test_xss.py` into the corresponding folders of your **existing** `D:\VulnScope` project. Do not replace your existing `app/app.py`.

In `app/app.py`, register the blueprint **after** `app = Flask(__name__)` and **before** starting the server:

```python
from xss_lab import xss_lab
app.register_blueprint(xss_lab)
```

Keep `app.run(host="127.0.0.1", port=5000)` and do not expose the lab to any network interface. This is a deliberately insecure educational route.

From `D:\VulnScope` in PowerShell, install needed dependencies into the active environment:

```powershell
python -m pip install flask requests
python .\app\app.py
```

In a SECOND terminal, while Flask is running:

```powershell
python .\scanner\test_xss.py
```

Open `http://127.0.0.1:5000/lab/xss` and test:

```html
<script>alert("VulnScope XSS test")</script>
```

The vulnerable page should show a browser alert. The same input at `http://127.0.0.1:5000/lab/xss-safe` should be shown as text with no alert.

**Do not deploy this demo publicly**. The test script checks only HTML reflection/escaping; it does not execute JavaScript.
