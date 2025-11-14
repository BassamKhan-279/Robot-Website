#!/usr/bin/env python3
import os
import threading
import subprocess
import pathlib
import json
import sys
import socket
import asyncio
import time
import aiohttp
from aiohttp import web, ClientSession
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session

# ---------- Configuration Constants ----------
USER_FACING_PORT = 8000
ROSBOARD_URL = "http://localhost:8888"
LOGIN_SERVER_URL = f"http://localhost:{USER_FACING_PORT}" 

# ---------- Paths ----------
BASE_DIR = pathlib.Path(__file__).parent
WEB_DIR = BASE_DIR / "web" # Confirmed correct path: rosboard/web/

# ---------- Supabase Config  ----------
SUPABASE_URL = "https://pxlbmyygaiqevnbcrnmj.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjMxMDU3NjUsImV4cCI6MjA3ODQ2NTc2NX0.dZGlpzwumKk2RkcuBr311UaxsT28hUu9fD027Qj8jhA"
SUPABASE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzEwNTc2NSwiZXhwIjoyMDc4NDY1NzY1fQ._-WhtBPNPhuVwap51TK4JL29EvhU9XELErT4dMhhr5o"

POSTGREST_BASE = f"{SUPABASE_URL}/rest/v1"
AUTH_BASE = f"{SUPABASE_URL}/auth/v1"

# --- Helper HTTP functions ---
def _supabase_headers():
    return {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

def _auth_headers(jwt=None):
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json"
    }
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    return headers

async def sb_auth_post(session: ClientSession, path: str, payload: dict):
    url = f"{AUTH_BASE}/{path}"
    async with session.post(url, headers=_auth_headers(), json=payload) as resp:
        try:
            data = await resp.json()
        except Exception:
            data = {"raw": await resp.text()}
        return resp.status, data
        
async def sb_admin_auth_post(session: ClientSession, path: str, payload: dict):
    url = f"{AUTH_BASE}/{path}"
    headers = {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}",
        "Content-Type": "application/json"
    }
    async with session.post(url, headers=headers, json=payload) as resp:
        try:
            data = await resp.json()
        except Exception:
            data = {"raw": await resp.text()}
        return resp.status, data

async def sb_get(session: ClientSession, path: str, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.get(url, headers=_supabase_headers(), params=params) as resp:
        try:
            return resp.status, await resp.json()
        except Exception:
            return resp.status, {"error": await resp.text()}

async def sb_post(session: ClientSession, path: str, payload: dict):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.post(url, headers=_supabase_headers(), data=json.dumps(payload)) as resp:
        try:
            return resp.status, await resp.json()
        except Exception:
            return resp.status, {"raw": await resp.text()}

async def sb_patch(session: ClientSession, path: str, payload: dict, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.patch(url, headers=_supabase_headers(), params=params, json=payload) as resp:
        try:
            return resp.status, await resp.json()
        except Exception:
            return resp.status, {"raw": await resp.text()}

async def sb_delete(session: ClientSession, path: str, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.delete(url, headers=_supabase_headers(), params=params) as resp:
        if resp.status == 204: # 204 No Content is success for delete
            return resp.status, {"status": "deleted"}
        try:
            return resp.status, await resp.json()
        except Exception:
            return resp.status, {"raw": await resp.text()}

# ---------- App startup / cleanup  ----------
async def on_startup(app):
    print("[Supabase] Creating HTTP client session")
    app["http_client"] = ClientSession()

async def on_cleanup(app):
    print("[Supabase] Closing HTTP client session")
    await app["http_client"].close()


# ---------- Login ----------
async def login_page(request):
    login_path = WEB_DIR / "login.html"
    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        pwd = data.get("password")

        print(f"[Login Debug] Attempting Supabase login for {email}")

        login_payload = {"email": email, "password": pwd}
        async with request.app["http_client"].post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers={"apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json"},
            json=login_payload
        ) as resp:
            result = await resp.json()
            
            if resp.status != 200:
                print(f"[Login] ❌ Auth failed: {result.get('error_description', 'Invalid credentials')}")
                return web.Response(text="Invalid credentials. Please try again.", content_type='text/html')

            print(f"[Login] Auth success. Fetching profile for {email}...")
            params = {"email": f"eq.{email}", "select": "role,id"}
            status, profile_data = await sb_get(request.app["http_client"], "profiles", params=params)
            
            role = "user" 
            user_id = None
            if status == 200 and profile_data:
                role = profile_data[0].get("role", "user")
                user_id = profile_data[0].get("id")
                print(f"[Login] Profile found. Role: {role}")
            else:
                print(f"[Login] ⚠️ No profile found for {email}, defaulting to 'user' role.")

            # CRITICAL: This is where the session is created with the role.
            session_data = await get_session(request)
            session_data["user"] = {"email": email, "role": role, "id": user_id}
            
            print(f"[Login] ✅ {email} logged in successfully as {role}.")
            # REDIRECT to the ROSBoard URL (localhost:8888)
            raise web.HTTPFound(ROSBOARD_URL)

    return web.FileResponse(login_path)

# -------------------------------------------------------------
#   SECURE PAGE HANDLERS (Redirect to ROSBoard after login)
# -------------------------------------------------------------

async def index_page(request):
    """After login, redirects to the main ROSBoard URL."""
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound(f"{LOGIN_SERVER_URL}/login")
    # Redirect directly to ROSBoard's root URL (localhost:8888)
    raise web.HTTPFound(ROSBOARD_URL)


# --- Logout, Register, Forgot Password, Admin, API Endpoints  ---
async def logout(request):
    session = await get_session(request)
    session.invalidate()
    print("[Logout] User logged out.")
    raise web.HTTPFound(f"{LOGIN_SERVER_URL}/login")

# 🟢 CORRECTED HANDLER NAME FOR CONSISTENCY
async def reset_password_handler(request):
    """
    Handles the password reset submission by calling the Supabase API directly.
    """
    try:
        data = await request.post()
        access_token = data.get("access_token")
        new_password = data.get("password")

        if not access_token or not new_password:
            return web.Response(text="Missing token or password.", status=400)
        
        # NOTE: Supabase uses the access token to identify and update the user.
        # We perform the password change via the standard PUT /user endpoint, 
        # using the provided access_token for authentication.

        url = f"{AUTH_BASE}/user"
        headers = {
            "apikey": SUPABASE_ANON_KEY,
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {"password": new_password}

        async with request.app["http_client"].put(url, headers=headers, json=payload) as resp:
            if resp.status == 200:
                print(f"[Reset] ✅ Password updated via token.")
                # We return a simple text success message for the JS to display
                return web.Response(text="Password successfully reset.", status=200)
            else:
                error_data = await resp.json()
                error_msg = error_data.get('msg', 'Invalid or expired token. Please request a new link.')
                print(f"[Reset] ❌ Failed to update password: {error_msg}")
                # We return a simple text error message for the JS to display
                return web.Response(text=f"Reset failed: {error_msg}", status=resp.status)

    except Exception as e:
        print(f"[Reset] Internal error: {e}")
        return web.Response(text="An internal server error occurred during reset.", status=500)


async def register_page(request):
    register_path = WEB_DIR / "register.html"
    if request.method == "POST":
        data = await request.post()
        email, password = data.get("email"), data.get("password")
        role = data.get("role", "user") 
        
        print(f"[Register] Attempting Auth signup for {email} (Role: {role})")
        signup_payload = {"email": email, "password": password}
        auth_status, auth_result = await sb_auth_post(
            request.app["http_client"], "signup", signup_payload
        )
        
        if auth_status not in [200, 201]:
            error_msg = auth_result.get('msg', 'Authentication signup failed')
            print(f"[Register] ❌ Auth signup failed: {error_msg}")
            return web.Response(text=f"Registration failed: {error_msg}", status=auth_status)
        
        print(f"[Register] ✅ Auth user created: {email}")

        auth_user_id = None
        if 'id' in auth_result:
            auth_user_id = auth_result.get('id')
        elif 'user' in auth_result and 'id' in auth_result['user']:
            auth_user_id = auth_result['user'].get('id')

        if not auth_user_id:
            print(f"[Register] ❌ CRITICAL: Could not get user ID from Supabase auth result: {auth_result}")
            return web.Response(text="Registration failed (could not get user ID)", status=500)
        
        profile_payload = {"email": email, "role": role, "id": auth_user_id}
        
        profile_status, profile_created = await sb_post(
            request.app["http_client"], "profiles", profile_payload
        )
        
        if profile_status in (200, 201):
            print(f"[Register] ✅ Profile created for: {email} as {role}")
            raise web.HTTPFound(f"{LOGIN_SERVER_URL}/login") # Use absolute path
        else:
            print(f"[Register] ❌ Profile creation failed: {profile_created}")
            return web.Response(text="Registration failed (profile creation error)", status=500)
            
    return web.FileResponse(register_path)

async def forgot_password_page(request):
    forgot_path = WEB_DIR / "forgot_password.html"
    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        
        print(f"[ForgotPassword] Initiating password recovery for {email}")
        payload = {"email": email}
        status, result = await sb_auth_post(
            request.app["http_client"], "recover", payload
        )

        if status == 200:
            print(f"[ForgotPassword] ✅ Recovery email sent to {email}")
            return web.Response(text="If your email is in our system, a password reset link has been sent.", status=200)
        else:
            print(f"[ForgotPassword] ❌ Recovery failed or email not found: {result}")
            return web.Response(text="If your email is in our system, a password reset link. Please check your spam folder.", status=200)
            
    return web.FileResponse(forgot_path)

async def require_admin(request):
    """Helper function to protect admin routes."""
    session = await get_session(request)
    user = session.get("user")
    if not user or user.get("role") != "admin":
        print(f"[Security] ❌ Admin access denied for user: {user.get('email')}")
        raise web.HTTPForbidden(text="You must be an admin to access this page.")
    print(f"[Security] ✅ Admin access granted for: {user.get('email')}")
    return user

async def get_user_session(request):
    """API endpoint for frontend to check who is logged in."""
    session = await get_session(request)
    if "user" in session:
        return web.json_response(session["user"])
    return web.json_response({"error": "Not logged in"}, status=401)

# 🚨 FINAL FIX HANDLER 🚨
async def admin_page(request):
    """
    Serves the admin.html page with explicit content type, 
    after verifying admin privileges.
    """
    await require_admin(request) # Protect this page

    # Path points to rosboard/web/admin.html (as confirmed by the user)
    admin_path = WEB_DIR / "admin.html"
    
    try:
        # CRITICAL FIX: Read the file content and set the MIME type manually
        with open(admin_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return web.Response(
            text=content,
            content_type='text/html' # Force the browser to render as HTML
        )
    except FileNotFoundError:
        # This handles the case if the file is missing in the /web/ directory
        return web.Response(text=f"Admin HTML file not found at: {admin_path}", status=500)
    except Exception as e:
        print(f"Error serving admin page: {e}")
        return web.Response(text="Error processing admin page content.", status=500)

async def get_users(request):
    """API for admins to get a list of all users."""
    await require_admin(request)
    params = {"select": "id,email,role"} # Get all users
    status, data = await sb_get(request.app["http_client"], "profiles", params=params)
    if status == 200:
        return web.json_response(data)
    return web.json_response({"error": "Failed to fetch users"}, status=status)

async def admin_create_user(request):
    """API for an admin to create a new user."""
    await require_admin(request)
    data = await request.json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")

    if not email or not password:
        return web.json_response({"error": "Email and password are required"}, status=400)
    
    print(f"[Admin] Attempting to create auth user for {email}")
    auth_payload = {
        "email": email, 
        "password": password,
        "email_confirm": True # Auto-confirm the email
    }
    auth_status, auth_result = await sb_admin_auth_post(
        request.app["http_client"], "admin/users", auth_payload
    )

    if auth_status not in [200, 201]:
        error_msg = auth_result.get('msg', 'Auth user creation failed')
        print(f"[Admin] ❌ Auth user creation failed: {error_msg}")
        return web.json_response({"error": f"Auth user creation failed: {error_msg}"}, status=auth_status)
    
    print(f"[Admin] ✅ Auth user created: {email}")
    
    # CRITICAL FIX: Extract user ID robustly
    auth_user_id = auth_result.get('id')
    
    if not auth_user_id:
        # Fallback 1: Check for UUID inside a nested 'user' object (for older responses)
        auth_user_id = auth_result.get('user', {}).get('id')
        
    if not auth_user_id:
        print(f"[Admin] ❌ CRITICAL: Could not extract user ID from auth result: {auth_result}")
        return web.json_response({"error": "Failed to retrieve user ID from authentication service for profile creation."}, status=500)

    profile_payload = {"email": email, "role": role, "id": auth_user_id}
    
    profile_status, profile_created = await sb_post(
        request.app["http_client"], "profiles", profile_payload
    )
    
    if profile_status in (200, 201):
        print(f"[Admin] ✅ Profile created for: {email} as {role}")
        return web.json_response(profile_created) # Return the new user object array
    else:
        print(f"[Admin] ❌ Profile creation failed: {profile_created}")
        return web.json_response({"error": "Profile creation failed"}, status=500)

async def update_user_role(request):
    """API for admins to update a user's role."""
    await require_admin(request)
    user_id = request.match_info["id"]
    data = await request.json()
    new_role = data.get("role")

    if new_role not in ["user", "admin"]:
        return web.json_response({"error": "Invalid role specified"}, status=400)

    params = {"id": f"eq.{user_id}"}
    payload = {"role": new_role}
    
    status, res = await sb_patch(request.app["http_client"], "profiles", payload, params=params)
    
    if status in [200, 204]:
        print(f"[Admin] Updated role for user {user_id} to {new_role}")
        return web.json_response({"status": "updated"})
    return web.json_response({"error": "Failed to update role", "details": res}, status=status)

async def delete_user(request):
    """API for admins to delete a user."""
    await require_admin(request)
    user_id = request.match_info["id"]
    
    url = f"{AUTH_BASE}/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}"
    }
    
    async with request.app["http_client"].delete(url, headers=headers) as resp:
        if resp.status == 200:
            print(f"[Admin] 🗑️ Deleted user {user_id} from auth.")
            return web.json_response({"status": "deleted"})
        else:
            print(f"[Admin] ❌ Failed to delete auth user {user_id}: {await resp.text()}")
            return web.json_response({"error": "Failed to delete user"}, status=resp.status)


# 🟢 CORS MIDDLEWARE (Fixes the redirect loop)
@web.middleware
async def cors_middleware(request, handler):
    # This URL is the origin we allow to make requests (your ROSBoard server)
    ROSBOARD_ORIGIN = 'http://localhost:8888'

    # Handle preflight requests (OPTIONS method)
    if request.method == 'OPTIONS':
        response = web.Response()
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Origin'] = ROSBOARD_ORIGIN
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    # Process the actual request
    response = await handler(request)

    # Add CORS headers to the response
    response.headers['Access-Control-Allow-Origin'] = ROSBOARD_ORIGIN
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


# ---------- Middleware ----------
@web.middleware
async def require_login_middleware(request, handler):
    path = request.path
    
    # These paths are public on the login server (port 8000)
    public_paths = [
        "/login", "/register", "/forgot-password", "/static", 
        "/logout", "/api/get_session" 
    ]
    # We must also allow POST to /reset_password
    if path == "/reset_password" and request.method == "POST":
        return await handler(request)

    if any(path.startswith(p) for p in public_paths):
        return await handler(request)

    session = await get_session(request)
    if "user" not in session:
        if path.startswith("/api/"): 
            return web.json_response({"error": "Not authenticated"}, status=401)
        
        print(f"[Security] No session, redirecting to /login (requested path: {path})")
        # 🚨 FINAL FIX: Use absolute URL redirect to port 8000
        raise web.HTTPFound(f"{LOGIN_SERVER_URL}/login")
    
    return await handler(request)

# ---------- Main  ----------
def main():
    print(f"[LoginServer] 🔧 Starting Login/Admin server on port {USER_FACING_PORT}...")
    
    app = web.Application(middlewares=[
        # 🟢 NEW: Register the CORS middleware first
        cors_middleware,
        aiohttp_session.session_middleware(SimpleCookieStorage()),
        require_login_middleware
    ])
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Routes (all relative to the new port 8000)
    app.router.add_get("/", login_page) # Root is now the login page
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_page)
    app.router.add_get("/logout", logout)
    app.router.add_get("/register", register_page)
    app.router.add_post("/register", register_page)
    app.router.add_get("/forgot-password", forgot_password_page)
    app.router.add_post("/forgot-password", forgot_password_page)
    app.router.add_post("/reset_password", reset_password_handler)
    
    # Admin Page Route
    app.router.add_get("/admin", admin_page)

    # API Routes
    app.router.add_get("/api/get_session", get_user_session)
    app.router.add_get("/api/users", get_users)
    app.router.add_post("/api/users", admin_create_user) 
    app.router.add_put("/api/users/{id}/role", update_user_role)
    app.router.add_delete("/api/users/{id}", delete_user)

    app.router.add_static("/static/", path=str(WEB_DIR / "static"), name="static")

    print(f"[LoginServer] ✅ Server running at: http://localhost:{USER_FACING_PORT}")
    web.run_app(app, host="0.0.0.0", port=USER_FACING_PORT)

if __name__ == "__main__":
    main()
