import streamlit as st
import requests
import os
from urllib.parse import urlencode
from supabase import create_client, Client

# --- Streamlit Secrets Configuration ---
try:
    # Production: Use Streamlit secrets
    SUPABASE_URL = st.secrets["supabase"]["url"]
    SUPABASE_KEY = st.secrets["supabase"]["anon_key"]
    GITLAB_CLIENT_ID = st.secrets["gitlab"]["client_id"]
    GITLAB_CLIENT_SECRET = st.secrets["gitlab"]["client_secret"]
    GITLAB_REDIRECT_URI = st.secrets["gitlab"]["redirect_uri"]
    
except Exception as e:
    # Local development fallback
    st.warning("⚠️ Streamlit secrets not found. Using environment variables for local development.")
    SUPABASE_URL = os.getenv("SUPABASE_URL", "your_supabase_url")
    SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "your_anon_key")
    GITLAB_CLIENT_ID = os.getenv("GITLAB_CLIENT_ID", "your_client_id")
    GITLAB_CLIENT_SECRET = os.getenv("GITLAB_CLIENT_SECRET", "your_client_secret")
    GITLAB_REDIRECT_URI = os.getenv("GITLAB_REDIRECT_URI", "http://localhost:8501")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- Authentication Functions ---
def init_session_state():
    """Initialize session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'home'
    if 'login_error' not in st.session_state:
        st.session_state.login_error = None

def require_auth():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)

def logout():
    """Logout current user"""
    st.session_state.authenticated = False
    st.session_state.current_user = None
    st.success("✅ Logged out successfully!")
    st.rerun()

def login_with_gitlab():
    """Redirect to GitLab for authentication"""
    gitlab_auth_url = "https://code.swecha.org/oauth/authorize"
    params = {
        "client_id": GITLAB_CLIENT_ID,
        "redirect_uri": GITLAB_REDIRECT_URI,
        "response_type": "code",
        "scope": "read_user"
    }
    st.experimental_set_query_params()  # Clear any existing query params
    st.markdown(f"[Login with GitLab]({gitlab_auth_url}?{urlencode(params)})")

def handle_gitlab_callback():
    """Handle the callback from GitLab after authentication"""
    code = st.experimental_get_query_params().get("code", [None])[0]
    if code:
        token_url = "https://code.swecha.org/oauth/token"
        token_data = {
            "client_id": GITLAB_CLIENT_ID,
            "client_secret": GITLAB_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GITLAB_REDIRECT_URI
        }
        response = requests.post(token_url, data=token_data)
        if response.status_code == 200:
            token_info = response.json()
            access_token = token_info.get("access_token")
            user_info = get_gitlab_user_info(access_token)
            if user_info:
                st.session_state.authenticated = True
                st.session_state.current_user = user_info
                st.success("✅ Login successful!")
                st.experimental_set_query_params()  # Clear query params
                st.experimental_rerun()
        else:
            st.error("❌ Failed to authenticate with GitLab")

def get_gitlab_user_info(access_token):
    """Get user information from GitLab using the access token"""
    user_url = "https://code.swecha.org/api/v4/user"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(user_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

# --- Supabase Storage Functions ---
def upload_file_to_supabase(file):
    """Upload a file to Supabase storage"""
    if file is not None:
        file_name = file.name
        response = supabase.storage.from_("resources").upload(file_name, file)
        if response.status_code == 200:
            st.success("✅ File uploaded successfully!")
        else:
            st.error("❌ Failed to upload file.")

def list_files_in_supabase():
    """List files in Supabase storage"""
    files = supabase.storage.from_("resources").list()
    return files

# --- Main Application Logic ---
def main():
    # Initialize session state
    init_session_state()
    
    # Check for GitLab callback
    if "code" in st.experimental_get_query_params():
        handle_gitlab_callback()
    
    # Check authentication
    if not require_auth():
        st.title("🔐 V-Learn Login")
        login_with_gitlab()
        return
    
    # Sidebar navigation
    with st.sidebar:
        st.title("📚 V-Learn")
        st.markdown("---")
        
        # User info
        current_user = st.session_state.current_user
        if current_user:
            st.write(f"👋 Welcome, **{current_user['name']}**!")
            st.markdown("---")
        
        # Navigation menu
        menu_options = {
            "🏠 Home": "home",
            "📁 Resources": "resources",
            "🚀 Projects": "projects"
        }
        
        for label, page in menu_options.items():
            if st.button(label, use_container_width=True):
                st.session_state.current_page = page
        
        # Logout button
        if st.button("🚪 Logout", use_container_width=True):
            logout()
    
    # Main content area
    current_page = st.session_state.current_page
    
    if current_page == 'home':
        st.title("📚 V-Learn: Learning Resources on the Go")
        st.markdown("*Your community-driven learning platform*")
        st.markdown("---")
        # Add your main page content here
    elif current_page == 'resources':
        st.title("📁 Resource Library")
        uploaded_file = st.file_uploader("Upload a file", type=["pdf", "docx", "txt", "jpg", "png"])
        if st.button("Upload"):
            upload_file_to_supabase(uploaded_file)
        
        st.markdown("---")
        st.subheader("Uploaded Files")
        files = list_files_in_supabase()
        for file in files:
            st.write(file['name'])
    elif current_page == 'projects':
        # Add your project showcase page logic here
        pass

    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #666; padding: 20px;'>
        📚 V-Learn - Community Learning Platform | 
        Built with ❤️ using Streamlit & Supabase
        </div>
        """, 
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()
