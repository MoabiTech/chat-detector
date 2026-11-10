# Run the Windows prototype

The detector is a Streamlit web application. A PyInstaller `--onefile` build of
`app.py` is not a verified standalone executable because it must start a local
Streamlit server and include the project's Python dependencies.

## Setup and run

From PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
.\start_detector.bat
```

The launcher starts the Streamlit interface in the browser. For a true standalone
executable, package and test the complete Streamlit runtime and dependencies as a
separate release task; do not submit an unverified PyInstaller output as a working
application.

## Run the chat demo

From the `e2ee_chat` folder, run `start_server.bat`, then open
http://127.0.0.1:5001/. On its first run the script creates a local virtual
environment and installs the chat dependencies.
