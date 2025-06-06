import streamlit as st
import json
import os
from datetime import datetime
from tempfile import NamedTemporaryFile
import hashlib
import mimetypes
from supabase import create_client, Client
import uuid
import secrets
import re

# --- Streamlit Secrets Configuration ---
try:
    # Production: Use Streamlit secrets
    SUPABASE_URL = st.secrets["supabase"]["url"]
    SUPABASE_KEY = st.secrets["supabase"]["anon_key"]
    SUPABASE_SERVICE_KEY = st.secrets["supabase"]["service_role_key"]
    ADMIN_PASSWORD = st.secrets.get("admin", {}).get("password", "admin123")
    
except Exception as e:
    # Local development fallback
    st.warning("⚠️ Streamlit secrets not found. Using environment variables for local development.")
    SUPABASE_URL = os.getenv("SUPABASE_URL", "your_supabase_url")
    SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "your_anon_key")
    SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "your_service_key")
    ADMIN_PASSWORD = "admin123"

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# Page configuration
st.set_page_config(
    page_title="V-Learn",
    page_icon="📚",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
    if 'register_error' not in st.session_state:
        st.session_state.register_error = None
    if 'register_success' not in st.session_state:
        st.session_state.register_success = None

def require_auth():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)

def get_current_user():
    """Get current user info"""
    return st.session_state.get('current_user', None)

def logout():
    """Logout current user"""
    st.session_state.authenticated = False
    st.session_state.current_user = None
    st.success("✅ Logged out successfully!")
    st.rerun()

def hash_password(password, salt=None):
    """Hash password with salt for secure storage"""
    if not salt:
        salt = secrets.token_hex(16)
    
    # Combine password and salt then hash
    combined = password + salt
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    
    return hashed, salt

def verify_password(input_password, stored_hash, stored_salt):
    """Verify password against stored hash and salt"""
    input_hash, _ = hash_password(input_password, stored_salt)
    return input_hash == stored_hash

def login_page():
    """Display login page with authentication options"""
    st.title("🔐 V-Learn Login")
    
    # Create a clean, visually appealing layout
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Create tabs for login and signup
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Sign Up"])
        
        with tab1:
            st.subheader("Welcome Back!")
            
            # Display any login errors
            if st.session_state.login_error:
                st.error(st.session_state.login_error)
                st.session_state.login_error = None
                
            # Login form
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Your username")
                password = st.text_input("Password", type="password", placeholder="Your password")
                
                login_submitted = st.form_submit_button("Login", use_container_width=True)
                
                if login_submitted:
                    if username == "demo" and password == "demo123":
                        # Demo user login
                        st.session_state.authenticated = True
                        st.session_state.current_user = {
                            "username": "demo",
                            "full_name": "Demo User",
                            "email": "demo@example.com",
                            "role": "user"
                        }
                        st.success("✅ Login successful!")
                        st.rerun()
                    elif authenticate_user(username, password):
                        st.success("✅ Login successful!")
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password")
            
            # Demo user info
            st.markdown("---")
            st.markdown("**Try with our demo account:**")
            st.code("Username: demo\nPassword: demo123")
        
        with tab2:
            st.subheader("Create Account")
            
            # Display registration messages
            if st.session_state.register_success:
                st.success(st.session_state.register_success)
                st.session_state.register_success = None
            
            if st.session_state.register_error:
                st.error(st.session_state.register_error)
                st.session_state.register_error = None
            
            # Registration form
            with st.form("register_form"):
                full_name = st.text_input("Full Name", placeholder="Your full name")
                email = st.text_input("Email Address", placeholder="Your email")
                new_username = st.text_input("Username", placeholder="Choose a username (min 4 characters)")
                
                col1, col2 = st.columns(2)
                with col1:
                    new_password = st.text_input("Password", type="password", 
                                              placeholder="Min 8 characters", 
                                              help="At least 8 characters with letters and numbers")
                with col2:
                    confirm_password = st.text_input("Confirm Password", type="password",
                                                  placeholder="Repeat password")
                
                # Terms acceptance
                terms_accepted = st.checkbox("I accept the Terms of Service and Privacy Policy")
                
                register_submitted = st.form_submit_button("Create Account", use_container_width=True)
                
                if register_submitted:
                    # Validate form data
                    if register_user(new_username, email, new_password, confirm_password, full_name, terms_accepted):
                        st.session_state.register_success = "✅ Account created successfully! Please login."
                        st.rerun()

def authenticate_user(username, password):
    """Authenticate user against the database"""
    try:
        # Check if username exists
        result = supabase.table("users").select("*").eq("username", username).execute()
        
        if not result.data or len(result.data) == 0:
            st.session_state.login_error = "Invalid username or password"
            return False
        
        user_data = result.data[0]
        
        # Verify password
        if verify_password(password, user_data.get("password_hash", ""), user_data.get("password_salt", "")):
            # Update last login timestamp
            supabase.table("users").update({"last_login": datetime.now().isoformat()}).eq("id", user_data["id"]).execute()
            
            # Set session state
            st.session_state.authenticated = True
            st.session_state.current_user = {
                "id": user_data["id"],
                "username": user_data["username"],
                "full_name": user_data.get("full_name", username),
                "email": user_data.get("email", ""),
                "role": user_data.get("role", "user")
            }
            
            return True
        else:
            st.session_state.login_error = "Invalid username or password"
            return False
            
    except Exception as e:
        st.session_state.login_error = f"Authentication error: {str(e)}"
        return False

def register_user(username, email, password, confirm_password, full_name, terms_accepted):
    """Register new user with validation"""
    # Validate inputs
    errors = []
    
    if not username or len(username) < 4:
        errors.append("Username must be at least 4 characters")
    
    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        errors.append("Please enter a valid email address")
    
    if not full_name or len(full_name) < 3:
        errors.append("Please enter your full name (at least 3 characters)")
    
    if not password or len(password) < 8:
        errors.append("Password must be at least 8 characters")
    elif not (re.search(r"[A-Za-z]", password) and re.search(r"[0-9]", password)):
        errors.append("Password must contain both letters and numbers")
    
    if password != confirm_password:
        errors.append("Passwords don't match")
    
    if not terms_accepted:
        errors.append("You must accept the Terms of Service")
    
    # Check if any validation errors
    if errors:
        st.session_state.register_error = "\n".join(errors)
        return False
    
    try:
        # Check if username exists
        username_check = supabase.table("users").select("id").eq("username", username).execute()
        if username_check.data and len(username_check.data) > 0:
            st.session_state.register_error = "Username is already taken"
            return False
        
        # Check if email exists
        email_check = supabase.table("users").select("id").eq("email", email).execute()
        if email_check.data and len(email_check.data) > 0:
            st.session_state.register_error = "Email is already registered"
            return False
        
        # Hash password
        password_hash, password_salt = hash_password(password)
        
        # Create user record
        user_data = {
            "username": username,
            "email": email,
            "full_name": full_name,
            "password_hash": password_hash,
            "password_salt": password_salt,
            "created_at": datetime.now().isoformat(),
            "last_login": datetime.now().isoformat(),
            "role": "user"
        }
        
        result = supabase.table("users").insert(user_data).execute()
        
        if result.data and len(result.data) > 0:
            return True
        else:
            st.session_state.register_error = "Registration failed. Please try again."
            return False
            
    except Exception as e:
        st.session_state.register_error = f"Registration error: {str(e)}"
        return False

# --- Supabase Database Manager ---
class SupabaseManager:
    def __init__(self):
        self.client = supabase
        self.admin_client = supabase_admin
        self.init_database()
    
    def init_database(self):
        """Initialize Supabase tables (this should be done via Supabase SQL editor)"""
        # This is for reference - you should create these tables in Supabase SQL editor
        create_tables_sql = """
        -- Users table
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            full_name TEXT,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_login TIMESTAMPTZ,
            role TEXT DEFAULT 'user'
        );

        -- Resources table
        CREATE TABLE IF NOT EXISTS resources (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            file_url TEXT,
            external_url TEXT,
            file_type TEXT,
            resource_type TEXT,
            file_size BIGINT,
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            tags TEXT,
            downloads INTEGER DEFAULT 0,
            likes INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            user_id UUID REFERENCES users(id)
        );

        -- Projects table
        CREATE TABLE IF NOT EXISTS projects (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            technologies TEXT,
            github_url TEXT,
            demo_url TEXT,
            image_url TEXT,
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            likes INTEGER DEFAULT 0,
            views INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            user_id UUID REFERENCES users(id)
        );

        -- User data table
        CREATE TABLE IF NOT EXISTS user_data (
            id SERIAL PRIMARY KEY,
            user_id UUID REFERENCES users(id),
            bookmarks JSONB,
            completed JSONB,
            preferences JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        -- Analytics table
        CREATE TABLE IF NOT EXISTS analytics (
            id SERIAL PRIMARY KEY,
            event_type TEXT,
            resource_id INTEGER,
            user_id UUID REFERENCES users(id),
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            metadata JSONB
        );

        -- Enable Row Level Security
        ALTER TABLE users ENABLE ROW LEVEL SECURITY;
        ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
        ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
        ALTER TABLE user_data ENABLE ROW LEVEL SECURITY;
        ALTER TABLE analytics ENABLE ROW LEVEL SECURITY;

        -- Create policies for public read access
        CREATE POLICY "Public read access for resources" ON resources FOR SELECT USING (true);
        CREATE POLICY "Public read access for projects" ON projects FOR SELECT USING (true);
        CREATE POLICY "Users can insert resources" ON resources FOR INSERT WITH CHECK (auth.uid() = user_id OR user_id IS NULL);
        CREATE POLICY "Users can insert projects" ON projects FOR INSERT WITH CHECK (auth.uid() = user_id OR user_id IS NULL);
        """
        # Note: Execute this SQL in your Supabase SQL editor
        pass
    
    def add_resource(self, resource_data):
        """Add a new resource to the database"""
        try:
            result = self.client.table("resources").insert(resource_data).execute()
            if result.data:
                return result.data[0]['id']
            return None
        except Exception as e:
            st.error(f"Error adding resource: {str(e)}")
            return None
    
    def get_resources(self, limit=None):
        """Get resources from the database"""
        try:
            query = self.client.table("resources").select("*").order("timestamp", desc=True)
            if limit:
                query = query.limit(limit)
            result = query.execute()
            return result.data
        except Exception as e:
            st.error(f"Error fetching resources: {str(e)}")
            return []
    
    def add_project(self, project_data):
        """Add a new project to the database"""
        try:
            result = self.client.table("projects").insert(project_data).execute()
            if result.data:
                return result.data[0]['id']
            return None
        except Exception as e:
            st.error(f"Error adding project: {str(e)}")
            return None
    
    def get_projects(self, limit=None):
        """Get projects from the database"""
        try:
            query = self.client.table("projects").select("*").order("timestamp", desc=True)
            if limit:
                query = query.limit(limit)
            result = query.execute()
            return result.data
        except Exception as e:
            st.error(f"Error fetching projects: {str(e)}")
            return []
    
    def search_resources(self, query_text):
        """Search resources"""
        try:
            result = self.client.table("resources").select("*").or_(
                f"title.ilike.%{query_text}%,author.ilike.%{query_text}%,category.ilike.%{query_text}%,description.ilike.%{query_text}%"
            ).order("timestamp", desc=True).execute()
            return result.data
        except Exception as e:
            st.error(f"Error searching resources: {str(e)}")
            return []
    
    def delete_resource(self, resource_id):
        """Delete a resource"""
        try:
            # First get the resource to check for file URL
            resource = self.client.table("resources").select("file_url").eq("id", resource_id).execute()
            
            # Delete from storage if file exists
            if resource.data and resource.data[0].get('file_url'):
                file_path = self.extract_file_path_from_url(resource.data[0]['file_url'])
                if file_path:
                    self.delete_file_from_storage(file_path)
            
            # Delete from database
            result = self.client.table("resources").delete().eq("id", resource_id).execute()
            return True
        except Exception as e:
            st.error(f"Error deleting resource: {str(e)}")
            return False
    
    def delete_project(self, project_id):
        """Delete a project"""
        try:
            # First get the project to check for image URL
            project = self.client.table("projects").select("image_url").eq("id", project_id).execute()
            
            # Delete from storage if image exists
            if project.data and project.data[0].get('image_url'):
                file_path = self.extract_file_path_from_url(project.data[0]['image_url'])
                if file_path:
                    self.delete_file_from_storage(file_path)
            
            # Delete from database
            result = self.client.table("projects").delete().eq("id", project_id).execute()
            return True
        except Exception as e:
            st.error(f"Error deleting project: {str(e)}")
            return False
    
    def get_stats(self):
        """Get platform statistics"""
        try:
            # Get resource count
            resources_result = self.client.table("resources").select("id", count="exact").execute()
            total_resources = resources_result.count or 0
            
            # Get project count
            projects_result = self.client.table("projects").select("id", count="exact").execute()
            total_projects = projects_result.count or 0
            
            # Get total downloads
            downloads_result = self.client.table("resources").select("downloads").execute()
            total_downloads = sum(r.get('downloads', 0) for r in downloads_result.data) if downloads_result.data else 0
            
            # Get total likes (resources + projects)
            resource_likes_result = self.client.table("resources").select("likes").execute()
            resource_likes = sum(r.get('likes', 0) for r in resource_likes_result.data) if resource_likes_result.data else 0
            
            project_likes_result = self.client.table("projects").select("likes").execute()
            project_likes = sum(p.get('likes', 0) for p in project_likes_result.data) if project_likes_result.data else 0
            
            # Get user count
            users_result = self.client.table("users").select("id", count="exact").execute()
            total_users = users_result.count or 0
            
            return {
                'total_resources': total_resources,
                'total_projects': total_projects,
                'total_downloads': total_downloads,
                'total_likes': resource_likes + project_likes,
                'total_users': total_users
            }
        except Exception as e:
            st.error(f"Error fetching stats: {str(e)}")
            return {
                'total_resources': 0,
                'total_projects': 0,
                'total_downloads': 0,
                'total_likes': 0,
                'total_users': 0
            }
    
    def extract_file_path_from_url(self, url):
        """Extract file path from Supabase storage URL"""
        try:
            # Supabase storage URLs format: https://xxx.supabase.co/storage/v1/object/public/bucket/path
            if "/storage/v1/object/public/" in url:
                return url.split("/storage/v1/object/public/")[1]
            return None
        except:
            return None
    
    def delete_file_from_storage(self, file_path):
        """Delete file from Supabase storage"""
        try:
            bucket_name, file_path_in_bucket = file_path.split("/", 1)
            result = self.admin_client.storage.from_(bucket_name).remove([file_path_in_bucket])
            return True
        except Exception as e:
            st.error(f"Error deleting file from storage: {str(e)}")
            return False

# Initialize database manager
db_manager = SupabaseManager()

# --- Supabase Storage Upload Function ---
def upload_to_supabase(uploaded_file, bucket_name="vlearn"):
    """Upload file to Supabase Storage and return URL and metadata"""
    if not uploaded_file:
        return None
    
    try:
        # Generate unique filename
        file_hash = hashlib.md5(uploaded_file.getvalue()).hexdigest()[:10]
        file_extension = uploaded_file.name.split('.')[-1] if '.' in uploaded_file.name else ''
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file_hash}.{file_extension}"
        file_path = f"uploads/{filename}"
        
        # Upload to Supabase Storage
        result = supabase_admin.storage.from_(bucket_name).upload(
            file_path, 
            uploaded_file.getvalue(),
            file_options={
                "content-type": uploaded_file.type or "application/octet-stream"
            }
        )
        
        if result:
            # Get public URL
            public_url = supabase_admin.storage.from_(bucket_name).get_public_url(file_path)
            
            # Determine resource type
            resource_type = "image" if uploaded_file.type and uploaded_file.type.startswith("image") else \
                           "video" if uploaded_file.type and uploaded_file.type.startswith("video") else "file"
            
            return {
                "url": public_url,
                "file_path": file_path,
                "resource_type": resource_type,
                "format": file_extension,
                "bytes": len(uploaded_file.getvalue()),
                "created_at": datetime.now().isoformat()
            }
    except Exception as e:
        st.error(f"❌ Upload failed: {str(e)}")
        return None

# --- Admin Authentication ---
def check_admin_password():
    """Simple admin authentication"""
    if 'admin_authenticated' not in st.session_state:
        st.session_state.admin_authenticated = False
    
    if not st.session_state.admin_authenticated:
        st.subheader("🔐 Admin Login")
        password = st.text_input("Enter admin password:", type="password")
        if st.button("Login"):
            if password == ADMIN_PASSWORD:
                st.session_state.admin_authenticated = True
                st.success("✅ Admin authenticated!")
                st.rerun()
            else:
                st.error("❌ Invalid password")
        return False
    return True

# --- Utility Functions ---
def validate_url(url):
    """Simple URL validation"""
    if not url:
        return True
    return url.startswith(('http://', 'https://'))

def get_resource_icon(resource):
    """Get appropriate icon based on resource type"""
    if resource.get('external_url') and not resource.get('file_url'):
        return "🔗"
    elif resource.get('resource_type') == 'image':
        return "🖼️"
    elif resource.get('resource_type') == 'video':
        return "🎥"
    elif resource.get('file_type', '').startswith('application/pdf'):
        return "📄"
    else:
        return "📚"

def format_timestamp(timestamp_str):
    """Format timestamp for display"""
    try:
        if 'T' in timestamp_str:
            # ISO format from Supabase
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d %H:%M")
        else:
            # Already formatted
            return timestamp_str
    except:
        return timestamp_str

# --- Main App Pages ---
def main_page():
    st.title("📚 V-Learn: Learning Resources on the Go")
    st.markdown("*Your community-driven learning platform*")
    st.markdown("---")
    
    # Welcome section
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("📖 Documentation Hub")
        st.write("Access curated documentation for popular tools and technologies.")
        if st.button("Browse Documentation", use_container_width=True):
            st.session_state.current_page = "documentation"
    
    with col2:
        st.subheader("📁 Resource Library")
        st.write("Upload, share, and discover learning resources from the community.")
        if st.button("Explore Resources", use_container_width=True):
            st.session_state.current_page = "resources"
    
    with col3:
        st.subheader("🚀 Project Showcase")
        st.write("Showcase your projects and discover what others have built.")
        if st.button("View Projects", use_container_width=True):
            st.session_state.current_page = "projects"
    
    st.markdown("---")
    
    # Platform statistics
    st.subheader("📊 Platform Statistics")
    stats = db_manager.get_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📚 Total Resources", stats.get('total_resources', 0))
    with col2:
        st.metric("🚀 Projects Showcased", stats.get('total_projects', 0))
    with col3:
        st.metric("📥 Downloads", stats.get('total_downloads', 0))
    with col4:
        st.metric("❤️ Total Likes", stats.get('total_likes', 0))
    
    # Recent activity
    st.markdown("---")
    st.subheader("📈 Recent Activity")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**🆕 Latest Resources:**")
        recent_resources = db_manager.get_resources(limit=3)
        if recent_resources:
            for resource in recent_resources:
                icon = get_resource_icon(resource)
                with st.container():
                    st.write(f"{icon} **{resource['title']}** - {resource['category']}")
                    st.caption(f"By {resource['author']} | {format_timestamp(resource.get('timestamp', ''))}")
                    
                    # Show appropriate link
                    if resource.get('file_url'):
                        st.markdown(f"[📁 View File]({resource['file_url']})")
                    if resource.get('external_url'):
                        st.markdown(f"[🔗 External Link]({resource['external_url']})")
        else:
            st.info("No resources uploaded yet. Be the first to share!")
    
    with col2:
        st.write("**🆕 Latest Projects:**")
        recent_projects = db_manager.get_projects(limit=3)
        if recent_projects:
            for project in recent_projects:
                with st.container():
                    st.write(f"• **{project['title']}** - {project['category']}")
                    st.caption(f"By {project['author']} | {format_timestamp(project.get('timestamp', ''))}")
                    if project.get('demo_url'):
                        st.markdown(f"[🌐 Live Demo]({project['demo_url']})")
        else:
            st.info("No projects showcased yet. Share your work!")

def resource_library_page():
    st.title("📁 Resource Library")
    
    # Tabs for different actions
    tab1, tab2, tab3 = st.tabs(["📚 Browse Resources", "📤 Upload Resource", "🔍 Search"])
    
    with tab1:
        st.subheader("Available Resources")
        resources = db_manager.get_resources()
        
        if resources:
            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                categories = sorted(list(set([r['category'] for r in resources])))
                selected_category = st.selectbox("Filter by Category", ["All"] + categories)
            with col2:
                sort_by = st.selectbox("Sort by", ["Newest", "Most Downloads", "Most Likes"])
            
            # Apply filters
            filtered_resources = resources
            if selected_category != "All":
                filtered_resources = [r for r in resources if r['category'] == selected_category]
            
            # Sort resources
            if sort_by == "Most Downloads":
                filtered_resources.sort(key=lambda x: x.get('downloads', 0), reverse=True)
            elif sort_by == "Most Likes":
                filtered_resources.sort(key=lambda x: x.get('likes', 0), reverse=True)
            else:  # Newest
                filtered_resources.sort(key=lambda x: x.get('timestamp', ""), reverse=True)
            
            # Display resources
            for resource in filtered_resources:
                icon = get_resource_icon(resource)
                with st.expander(f"{icon} {resource['title']} - {resource['category']}"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.markdown(f"**Author:** {resource['author']}")
                        st.markdown(f"**Description:** {resource.get('description', 'No description')}")
                        st.markdown(f"**Category:** {resource['category']}")
                        st.markdown(f"**Uploaded:** {format_timestamp(resource.get('timestamp', 'Unknown'))}")
                        st.markdown(f"**Downloads:** {resource.get('downloads', 0)} | **Likes:** {resource.get('likes', 0)}")
                        
                        # Show both file and external links if available
                        links_col1, links_col2 = st.columns(2)
                        with links_col1:
                            if resource.get('file_url'):
                                st.markdown(f"[📁 Download File]({resource['file_url']})")
                        with links_col2:
                            if resource.get('external_url'):
                                st.markdown(f"[🔗 External Link]({resource['external_url']})")
                    
                    with col2:
                        if resource.get('resource_type') == 'image' and resource.get('file_url'):
                            try:
                                st.image(resource['file_url'], width=200)
                            except:
                                st.write("📷 Image preview unavailable")
                        elif resource.get('external_url') and not resource.get('file_url'):
                            st.write("🔗 External Resource")
        else:
            st.info("No resources available yet. Upload the first one!")
    
    with tab2:
        st.subheader("📤 Upload New Resource")
        
        # Ensure the user is authenticated
        if not require_auth():
            st.warning("⚠️ You need to be logged in to upload resources.")
            return
        
        # Resource type selection
        resource_type_option = st.radio(
            "What type of resource are you sharing?",
            options=["📁 File Upload", "🔗 External Link", "📁🔗 Both File and Link"],
            horizontal=True
        )
        
        with st.form("upload_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                title = st.text_input("Resource Title*", placeholder="e.g., Python Basics Tutorial")
                author = st.text_input("Your Name*", placeholder="e.g., John Doe")
                category = st.selectbox("Category*", [
                    "Programming", "Web Development", "Data Science", "Design", 
                    "Machine Learning", "Mobile Development", "DevOps", "Database",
                    "UI/UX", "Cybersecurity", "Cloud Computing", "Other"
                ])
            
            with col2:
                description = st.text_area("Description", placeholder="Brief description of the resource...")
                tags = st.text_input("Tags (comma-separated)", placeholder="python, tutorial, beginner")
            
            # Conditional inputs based on resource type
            uploaded_file = None
            external_url = ""
            
            if resource_type_option in ["📁 File Upload", "📁🔗 Both File and Link"]:
                uploaded_file = st.file_uploader(
                    "Choose a file (images, videos, PDFs, documents)", 
                    type=["jpg", "jpeg", "png", "gif", "mp4", "mov", "avi", "pdf", "txt", "docx", "pptx", "xlsx", "zip"]
                )
            
            if resource_type_option in ["🔗 External Link", "📁🔗 Both File and Link"]:
                external_url = st.text_input(
                    "External URL", 
                    placeholder="https://example.com/resource",
                    help="Link to external resource (website, article, tutorial, etc.)"
                )
            
            submitted = st.form_submit_button("📤 Upload Resource", use_container_width=True)
            
            # Validation and submission
            if submitted and title and author:
                # Validate inputs based on resource type
                is_valid = True
                error_messages = []
                
                if resource_type_option == "📁 File Upload" and not uploaded_file:
                    error_messages.append("Please upload a file.")
                    is_valid = False
                elif resource_type_option == "🔗 External Link" and not external_url:
                    error_messages.append("Please provide an external URL.")
                    is_valid = False
                elif resource_type_option == "📁🔗 Both File and Link" and not uploaded_file and not external_url:
                    error_messages.append("Please provide either a file or an external URL (or both).")
                    is_valid = False
                
                # Validate URL format
                if external_url and not validate_url(external_url):
                    error_messages.append("Please enter a valid URL (starting with http:// or https://).")
                    is_valid = False
                
                if is_valid:
                    resource_data = {
                        "title": title,
                        "author": author,
                        "category": category,
                        "description": description,
                        "external_url": external_url or None,
                        "tags": tags,
                        "user_id": st.session_state.current_user["id"]
                    }
                    
                    # Handle file upload if present
                    if uploaded_file:
                        with st.spinner("🔄 Uploading file to Supabase..."):
                            upload_result = upload_to_supabase(uploaded_file)
                            
                            if upload_result:
                                resource_data.update({
                                    "file_url": upload_result["url"],
                                    "file_type": uploaded_file.type,
                                    "resource_type": upload_result["resource_type"],
                                    "file_size": upload_result["bytes"]
                                })
                            else:
                                st.error("File upload failed. Please try again.")
                                st.stop()
                    
                    # Save to database
                    resource_id = db_manager.add_resource(resource_data)
                    if resource_id:
                        st.success("✅ Resource uploaded successfully!")
                        
                        # Show preview
                        st.markdown("**Preview:**")
                        preview_col1, preview_col2 = st.columns(2)
                        
                        with preview_col1:
                            if resource_data.get("file_url"):
                                if resource_data.get("resource_type") == "image":
                                    st.image(resource_data["file_url"], width=300)
                                elif resource_data.get("resource_type") == "video":
                                    st.video(resource_data["file_url"])
                                else:
                                    st.markdown(f"[📁 View File]({resource_data['file_url']})")
                        
                        with preview_col2:
                            if resource_data.get("external_url"):
                                st.markdown(f"[🔗 External Link]({resource_data['external_url']})")
                                st.write(f"**External URL:** {resource_data['external_url']}")
                        
                        st.balloons()
                    else:
                        st.error("Failed to save resource. Please try again.")
                else:
                    for error in error_messages:
                        st.error(error)
            elif submitted:
                st.error("Please fill in all required fields.")
    
    def project_showcase_page():
        st.title("🚀 Project Showcase")
        
        tab1, tab2 = st.tabs(["🎯 Browse Projects", "📤 Share Project"])
        
        with tab1:
            st.subheader("Community Projects")
            projects = db_manager.get_projects()
            
            if projects:
                # Filter and sort options
                col1, col2 = st.columns(2)
                with col1:
                    categories = sorted(list(set([p['category'] for p in projects])))
                    selected_category = st.selectbox("Filter by Category", ["All"] + categories, key="project_filter")
                with col2:
                    sort_by = st.selectbox("Sort by", ["Newest", "Most Likes", "Most Views"], key="project_sort")
                
                # Apply filters
                filtered_projects = projects
                if selected_category != "All":
                    filtered_projects = [p for p in projects if p['category'] == selected_category]
                
                # Sort projects
                if sort_by == "Most Likes":
                    filtered_projects.sort(key=lambda x: x.get('likes', 0), reverse=True)
                elif sort_by == "Most Views":
                    filtered_projects.sort(key=lambda x: x.get('views', 0), reverse=True)
                else:  # Newest
                    filtered_projects.sort(key=lambda x: x.get('timestamp', ""), reverse=True)
                
                # Display projects
                for project in filtered_projects:
                    with st.expander(f"🚀 {project['title']} - {project['category']}"):
                        col1, col2 = st.columns([2, 1])
                        with col1:
                            st.markdown(f"**Author:** {project['author']}")
                            st.markdown(f"**Description:** {project.get('description', 'No description')}")
                            st.markdown(f"**Technologies:** {project.get('technologies', 'Not specified')}")
                            st.markdown(f"**Likes:** {project.get('likes', 0)} | **Views:** {project.get('views', 0)}")
                            
                            # Links
                            links_col1, links_col2 = st.columns(2)
                            with links_col1:
                                if project.get('github_url'):
                                    st.markdown(f"[📂 GitHub Repository]({project['github_url']})")
                            with links_col2:
                                if project.get('demo_url'):
                                    st.markdown(f"[🌐 Live Demo]({project['demo_url']})")
                        
                        with col2:
                            st.caption(f"Shared: {format_timestamp(project.get('timestamp', ''))}")
                            if project.get('image_url'):
                                try:
                                    st.image(project['image_url'], width=200)
                                except:
                                    st.write("📷 Image preview unavailable")
            else:
                st.info("No projects showcased yet. Share your work!")
        
        with tab2:
            st.subheader("Share Your Project")
            
            # Ensure the user is authenticated
            if not require_auth():
                st.warning("⚠️ You need to be logged in to share projects.")
                return
            
            with st.form("project_form"):
                col1, col2 = st.columns(2)
                with col1:
                    title = st.text_input("Project Title*", placeholder="e.g., Weather Dashboard App")
                    author = st.text_input("Your Name*", placeholder="e.g., Jane Smith")
                    category = st.selectbox("Category*", [
                        "Web Application", "Mobile App", "Data Science", "Machine Learning",
                        "Game", "Desktop Application", "API", "Library/Framework",
                        "DevOps Tool", "UI/UX Design", "Other"
                    ])
                    technologies = st.text_input("Technologies Used*", placeholder="e.g., React, Node.js, MongoDB")
                
                with col2:
                    description = st.text_area("Project Description", placeholder="Describe what your project does...")
                    github_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/username/repo")
                    demo_url = st.text_input("Live Demo URL", placeholder="https://yourproject.com")
                
                # Project image upload
                project_image = st.file_uploader(
                    "Project Screenshot/Image (optional)",
                    type=["jpg", "jpeg", "png", "gif"],
                    help="Upload a screenshot or image of your project"
                )
                
                submitted = st.form_submit_button("🚀 Share Project", use_container_width=True)
                
                if submitted and title and author and technologies:
                    # Validate URLs
                    is_valid = True
                    error_messages = []
                    
                    if github_url and not validate_url(github_url):
                        error_messages.append("Please enter a valid GitHub URL.")
                        is_valid = False
                    
                    if demo_url and not validate_url(demo_url):
                        error_messages.append("Please enter a valid demo URL.")
                        is_valid = False
                    
                    if is_valid:
                        project_data = {
                            "title": title,
                            "author": author,
                            "category": category,
                            "description": description,
                            "technologies": technologies,
                            "github_url": github_url or None,
                            "demo_url": demo_url or None,
                            "user_id": st.session_state.current_user["id"]
                        }
                        
                        # Handle image upload if present
                        if project_image:
                            with st.spinner("🔄 Uploading project image..."):
                                upload_result = upload_to_supabase(project_image)
                                
                                if upload_result:
                                    project_data["image_url"] = upload_result["url"]
                                else:
                                    st.warning("Image upload failed, but project will be saved without image.")
                        
                        # Save to database
                        project_id = db_manager.add_project(project_data)
                        if project_id:
                            st.success("✅ Project shared successfully!")
                            
                            # Show preview
                            st.markdown("**Preview:**")
                            if project_data.get("image_url"):
                                st.image(project_data["image_url"], width=400)
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                if project_data.get("github_url"):
                                    st.markdown(f"[📂 GitHub Repository]({project_data['github_url']})")
                            with col2:
                                if project_data.get("demo_url"):
                                    st.markdown(f"[🌐 Live Demo]({project_data['demo_url']})")
                            
                            st.balloons()
                        else:
                            st.error("Failed to share project. Please try again.")
                    else:
                        for error in error_messages:
                            st.error(error)
                elif submitted:
                    st.error("Please fill in all required fields (Title, Author, Technologies).")

def documentation_hub_page():
    st.title("📖 Documentation Hub")
    st.markdown("Quick access to popular documentation and learning resources")
    
    # Popular documentation categories
    doc_categories = {
        "🐍 Python": [
            {"name": "Python Official Docs", "url": "https://docs.python.org/3/", "desc": "Official Python documentation"},
            {"name": "Django", "url": "https://docs.djangoproject.com/", "desc": "High-level Python web framework"},
            {"name": "Flask", "url": "https://flask.palletsprojects.com/", "desc": "Lightweight web framework"},
            {"name": "FastAPI", "url": "https://fastapi.tiangolo.com/", "desc": "Modern, high-performance web framework"},
            {"name": "NumPy", "url": "https://numpy.org/doc/", "desc": "Numerical computing library"},
            {"name": "Pandas", "url": "https://pandas.pydata.org/docs/", "desc": "Data manipulation and analysis"},
        ],
        "🌐 Web Development": [
            {"name": "MDN Web Docs", "url": "https://developer.mozilla.org/", "desc": "Web development resources"},
            {"name": "React", "url": "https://react.dev/", "desc": "JavaScript library for UIs"},
            {"name": "Vue.js", "url": "https://vuejs.org/guide/", "desc": "Progressive JavaScript framework"},
            {"name": "Angular", "url": "https://angular.io/docs", "desc": "Platform for building mobile and desktop apps"},
            {"name": "Node.js", "url": "https://nodejs.org/docs/", "desc": "JavaScript runtime environment"},
            {"name": "Express.js", "url": "https://expressjs.com/", "desc": "Fast, minimalist web framework"},
        ],
        "☁️ Cloud & DevOps": [
            {"name": "AWS Documentation", "url": "https://docs.aws.amazon.com/", "desc": "Amazon Web Services docs"},
            {"name": "Google Cloud", "url": "https://cloud.google.com/docs", "desc": "Google Cloud Platform documentation"},
            {"name": "Azure", "url": "https://docs.microsoft.com/azure/", "desc": "Microsoft Azure documentation"},
            {"name": "Docker", "url": "https://docs.docker.com/", "desc": "Containerization platform"},
            {"name": "Kubernetes", "url": "https://kubernetes.io/docs/", "desc": "Container orchestration"},
            {"name": "Terraform", "url": "https://www.terraform.io/docs", "desc": "Infrastructure as code"},
        ],
        "🗄️ Databases": [
            {"name": "PostgreSQL", "url": "https://www.postgresql.org/docs/", "desc": "Advanced open source database"},
            {"name": "MongoDB", "url": "https://docs.mongodb.com/", "desc": "NoSQL document database"},
            {"name": "MySQL", "url": "https://dev.mysql.com/doc/", "desc": "Popular relational database"},
            {"name": "Redis", "url": "https://redis.io/documentation", "desc": "In-memory data structure store"},
            {"name": "Supabase", "url": "https://supabase.com/docs", "desc": "Open source Firebase alternative"},
        ],
        "🤖 AI/ML": [
            {"name": "TensorFlow", "url": "https://www.tensorflow.org/api_docs", "desc": "Machine learning platform"},
            {"name": "PyTorch", "url": "https://pytorch.org/docs/", "desc": "Deep learning framework"},
            {"name": "Scikit-learn", "url": "https://scikit-learn.org/stable/", "desc": "Machine learning library"},
            {"name": "Hugging Face", "url": "https://huggingface.co/docs", "desc": "NLP models and datasets"},
            {"name": "OpenAI API", "url": "https://platform.openai.com/docs", "desc": "AI API documentation"},
        ],
        "📱 Mobile Development": [
            {"name": "React Native", "url": "https://reactnative.dev/docs", "desc": "Cross-platform mobile development"},
            {"name": "Flutter", "url": "https://docs.flutter.dev/", "desc": "Google's UI toolkit"},
            {"name": "Swift", "url": "https://swift.org/documentation/", "desc": "iOS development language"},
            {"name": "Kotlin", "url": "https://kotlinlang.org/docs/", "desc": "Android development language"},
        ]
    }
    
    # Search functionality
    search_query = st.text_input("🔍 Search documentation...", placeholder="e.g., React, Python, Docker")
    
    if search_query:
        # Search through all documentation
        search_results = []
        for category, docs in doc_categories.items():
            for doc in docs:
                if (search_query.lower() in doc["name"].lower() or 
                    search_query.lower() in doc["desc"].lower()):
                    search_results.append({**doc, "category": category})
        
        if search_results:
            st.subheader(f"🔍 Search Results ({len(search_results)} found)")
            for result in search_results:
                with st.container():
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**[{result['name']}]({result['url']})** - {result['category']}")
                        st.caption(result['desc'])
                    with col2:
                        if st.button("Open", key=f"search_{result['name']}", use_container_width=True):
                            st.markdown(f"[🔗 Open {result['name']}]({result['url']})")
                    st.divider()
        else:
            st.info("No documentation found for your search query.")
    else:
        # Display categories
        st.subheader("📚 Popular Documentation")
        
        # Create tabs for each category
        tab_names = list(doc_categories.keys())
        tabs = st.tabs(tab_names)
        
        for i, (category, docs) in enumerate(doc_categories.items()):
            with tabs[i]:
                # Display docs in a grid
                cols = st.columns(2)
                for idx, doc in enumerate(docs):
                    with cols[idx % 2]:
                        with st.container():
                            st.markdown(f"**[{doc['name']}]({doc['url']})**")
                            st.caption(doc['desc'])
                            if st.button("Open Documentation", key=f"{category}_{doc['name']}", use_container_width=True):
                                st.markdown(f"[🔗 Open {doc['name']}]({doc['url']})")
                        st.markdown("---")

def admin_panel_page():
    st.title("🔧 Admin Panel")
    
    if not check_admin_password():
        return
    
    st.success("✅ Admin access granted")
    
    # Admin tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📚 Manage Resources", "🚀 Manage Projects", "⚙️ Settings"])
    
    with tab1:
        st.subheader("📊 Platform Dashboard")
        
        # Get comprehensive stats
        stats = db_manager.get_stats()
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("📚 Total Resources", stats.get('total_resources', 0))
        with col2:
            st.metric("🚀 Total Projects", stats.get('total_projects', 0))
        with col3:
            st.metric("📥 Total Downloads", stats.get('total_downloads', 0))
        with col4:
            st.metric("❤️ Total Likes", stats.get('total_likes', 0))
        
        st.markdown("---")
        
        # Recent activity
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📈 Recent Resources")
            recent_resources = db_manager.get_resources(limit=5)
            if recent_resources:
                for resource in recent_resources:
                    with st.container():
                        st.write(f"**{resource['title']}** by {resource['author']}")
                        st.caption(f"{resource['category']} | {format_timestamp(resource.get('timestamp', ''))}")
                        st.caption(f"Downloads: {resource.get('downloads', 0)} | Likes: {resource.get('likes', 0)}")
            else:
                st.info("No resources yet")
        
        with col2:
            st.subheader("🚀 Recent Projects")
            recent_projects = db_manager.get_projects(limit=5)
            if recent_projects:
                for project in recent_projects:
                    with st.container():
                        st.write(f"**{project['title']}** by {project['author']}")
                        st.caption(f"{project['category']} | {format_timestamp(project.get('timestamp', ''))}")
                        st.caption(f"Likes: {project.get('likes', 0)} | Views: {project.get('views', 0)}")
            else:
                st.info("No projects yet")
    
    with tab2:
        st.subheader("📚 Manage Resources")
        
        resources = db_manager.get_resources()
        if resources:
            for resource in resources:
                with st.expander(f"{resource['title']} - {resource['category']}"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"**ID:** {resource['id']}")
                        st.markdown(f"**Author:** {resource['author']}")
                        st.markdown(f"**Description:** {resource.get('description', 'No description')}")
                        st.markdown(f"**Downloads:** {resource.get('downloads', 0)} | **Likes:** {resource.get('likes', 0)}")
                        st.markdown(f"**Uploaded:** {format_timestamp(resource.get('timestamp', ''))}")
                        
                        if resource.get('file_url'):
                            st.markdown(f"[📁 View File]({resource['file_url']})")
                        if resource.get('external_url'):
                            st.markdown(f"[🔗 External Link]({resource['external_url']})")
                    
                    with col2:
                        if st.button("🗑️ Delete", key=f"del_resource_{resource['id']}", use_container_width=True):
                            if db_manager.delete_resource(resource['id']):
                                st.success("Resource deleted!")
                                st.rerun()
                            else:
                                st.error("Failed to delete resource")
        else:
            st.info("No resources to manage")
    
    with tab3:
        st.subheader("🚀 Manage Projects")
        
        projects = db_manager.get_projects()
        if projects:
            for project in projects:
                with st.expander(f"{project['title']} - {project['category']}"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"**ID:** {project['id']}")
                        st.markdown(f"**Author:** {project['author']}")
                        st.markdown(f"**Technologies:** {project.get('technologies', 'Not specified')}")
                        st.markdown(f"**Description:** {project.get('description', 'No description')}")
                        st.markdown(f"**Likes:** {project.get('likes', 0)} | **Views:** {project.get('views', 0)}")
                        st.markdown(f"**Shared:** {format_timestamp(project.get('timestamp', ''))}")
                        
                        if project.get('github_url'):
                            st.markdown(f"[📂 GitHub]({project['github_url']})")
                        if project.get('demo_url'):
                            st.markdown(f"[🌐 Live Demo]({project['demo_url']})")
                    
                    with col2:
                        if project.get('image_url'):
                            try:
                                st.image(project['image_url'], width=150)
                            except:
                                st.write("📷 Image unavailable")
                        
                        if st.button("🗑️ Delete", key=f"del_project_{project['id']}", use_container_width=True):
                            if db_manager.delete_project(project['id']):
                                st.success("Project deleted!")
                                st.rerun()
                            else:
                                st.error("Failed to delete project")
        else:
            st.info("No projects to manage")
    
    with tab4:
        st.subheader("⚙️ Platform Settings")
        
        st.markdown("**Current Configuration:**")
        st.code(f"""
        Supabase URL: {SUPABASE_URL[:50]}...
        Admin Password: {'*' * len(ADMIN_PASSWORD)}
        Database Status: Connected ✅
        Storage Status: Connected ✅
        """)
        
        st.markdown("**Database Health Check:**")
        try:
            # Test database connection
            test_resources = db_manager.get_resources(limit=1)
            test_projects = db_manager.get_projects(limit=1)
            st.success("✅ Database connection is healthy")
        except Exception as e:
            st.error(f"❌ Database connection issue: {str(e)}")

# --- Main Application Logic ---
def main():
    # Initialize session state
    init_session_state()
    
    # Check authentication
    if not require_auth():
        login_page()
        return
    
    # Sidebar navigation
    with st.sidebar:
        st.title("📚 V-Learn")
        st.markdown("---")
        
        # User info
        current_user = get_current_user()
        if current_user:
            if current_user.get('avatar_url'):
                st.image(current_user['avatar_url'], width=80)
            
            st.write(f"👋 Welcome, **{current_user['full_name']}**!")
            
            if current_user.get('gitlab_profile'):
                st.markdown(f"[🦊 GitLab Profile]({current_user['gitlab_profile']})")
            
            st.markdown("---")
        
        # Navigation menu
        menu_options = {
            "🏠 Home": "home",
            "📖 Documentation": "documentation", 
            "📁 Resources": "resources",
            "🚀 Projects": "projects"
        }
        
        # Add admin button for admins
        if current_user and current_user.get('role') == 'admin':
            menu_options["🔧 Admin"] = "admin"
        
        for label, page in menu_options.items():
            if st.button(label, use_container_width=True):
                st.session_state.current_page = page
        
        st.markdown("---")
        
        # Quick stats in sidebar
        stats = db_manager.get_stats()
        st.metric("📚 Resources", stats.get('total_resources', 0))
        st.metric("🚀 Projects", stats.get('total_projects', 0))
        
        st.markdown("---")
        st.markdown("**💡 Quick Tips:**")
        st.caption("• Upload files or share links")
        st.caption("• Showcase your projects")
        st.caption("• Browse documentation")
        st.caption("• Build and learn together!")
        
        # Logout button
        if st.button("🚪 Logout", use_container_width=True):
            logout()
    
    # Main content area
    current_page = st.session_state.current_page
    
    if current_page == 'home':
        main_page()
    elif current_page == 'documentation':
        documentation_hub_page()
    elif current_page == 'resources':
        resource_library_page()
    elif current_page == 'projects':
        project_showcase_page()
    elif current_page == 'admin':
        admin_panel_page()
    
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
