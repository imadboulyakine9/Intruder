"""
MongoDB database connection module for Intruder (Jarvis).
Handles connection pooling and database initialization.
"""

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import os
from dotenv import load_dotenv

load_dotenv()

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "intruder")
TIMEOUT = 5000  # milliseconds

class MongoDatabase:
    """MongoDB connection manager with singleton pattern."""
    
    _instance = None
    _client = None
    _db = None
    
    def __new__(cls):
        """Ensure only one database instance exists."""
        if cls._instance is None:
            cls._instance = super(MongoDatabase, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize MongoDB connection if not already connected."""
        if self._client is None:
            self.connect()
    
    @classmethod
    def connect(cls):
        """Establish connection to MongoDB."""
        try:
            cls._client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=TIMEOUT,
                connectTimeoutMS=TIMEOUT,
                retryWrites=True
            )
            # Test connection
            cls._client.admin.command('ping')
            cls._db = cls._client[DB_NAME]
            print(f"✓ Connected to MongoDB: {DB_NAME}")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"✗ MongoDB connection failed: {e}")
            raise
    
    @classmethod
    def get_db(cls):
        """Return the database instance."""
        if cls._db is None:
            instance = cls()
            return cls._db
        return cls._db
    
    @classmethod
    def close(cls):
        """Close MongoDB connection."""
        if cls._client:
            cls._client.close()
            cls._client = None
            cls._db = None
            print("✓ MongoDB connection closed")
    
    @classmethod
    def get_collection(cls, collection_name):
        """Get a specific collection."""
        db = cls.get_db()
        return db[collection_name]


# Initialize collections with indexes
def init_collections():
    """Create indexes for optimized queries."""
    db = MongoDatabase.get_db()
    
    # Scans collection
    scans = db["scans"]
    scans.create_index("target")
    scans.create_index("created_at")
    scans.create_index("status")
    
    # Subdomains collection
    subdomains = db["subdomains"]
    subdomains.create_index([("scan_id", 1), ("domain", 1)])
    
    # Vulnerabilities collection
    vulns = db["vulnerabilities"]
    vulns.create_index([("scan_id", 1), ("severity", 1)])
    vulns.create_index("tool")
    
    # Technologies collection
    tech = db["technologies"]
    tech.create_index([("scan_id", 1), ("name", 1)])

    # Assets collection (Asset-Centric View)
    assets = db["assets"]
    assets.create_index("domain", unique=True)
    assets.create_index("parent_domain")
    assets.create_index("ip")
    assets.create_index("technologies")
    
    print("✓ Database indexes created")


# Convenience functions for common operations
def get_scans_collection():
    """Get scans collection."""
    return MongoDatabase.get_collection("scans")


def get_assets_collection():
    """Get assets collection."""
    return MongoDatabase.get_collection("assets")


def get_subdomains_collection():
    """Get subdomains collection."""
    return MongoDatabase.get_collection("subdomains")


def get_vulnerabilities_collection():
    """Get vulnerabilities collection."""
    return MongoDatabase.get_collection("vulnerabilities")


def get_technologies_collection():
    """Get technologies collection."""
    return MongoDatabase.get_collection("technologies")


def get_attackable_urls_collection():
    """Get attackable URLs collection."""
    return MongoDatabase.get_collection("attackable_urls")


# Export main functions
db = MongoDatabase()


if __name__ == "__main__":
    # Test connection
    try:
        test_db = MongoDatabase()
        init_collections()
        print("✅ Database initialization successful!")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")