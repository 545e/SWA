# Installation Root Cause Report

## Defect Summary
Users previously reported that running `install.bat` would either stall, fail to find dependencies, or launch the browser to a non-responsive port.

## Investigation Details
1. **Python Path Resolution:** On systems with multiple Python installations or Microsoft Store stubs, `python` could launch the Store redirector if PATH precedence was incorrect.
2. **Port Conflict:** If port 8000 had lingering TIME_WAIT sockets, `find_available_port()` chose port 8001, while `run.bat` unconditionally launched `http://127.0.0.1:8000`.
3. **Resolution:**
   - Updated `run.bat` and `run.py` to communicate the exact bound URL.
   - Introduced dual-listener proxy on port 8001 ensuring both ports work seamlessly.
