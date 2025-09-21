#!/bin/bash

# 🗃️ Database Initialization Script for Countermeasure
# Initializes the database with schema and seed data

set -e  # Exit on any error

echo "🗃️ Initializing Countermeasure Database"
echo "====================================="

# Configuration
DB_HOST=${DATABASE_HOST:-localhost}
DB_PORT=${DATABASE_PORT:-5432}
DB_NAME=${DATABASE_NAME:-countermeasure_dev}
DB_USER=${DATABASE_USER:-countermeasure}
PGPASSWORD=${DATABASE_PASSWORD:-secretpassword}

export PGPASSWORD

echo "📋 Database Configuration:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo ""

# Wait for database to be ready
echo "⏳ Waiting for database to be ready..."
timeout=30
while ! pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; do
    timeout=$((timeout - 1))
    if [ $timeout -le 0 ]; then
        echo "❌ Database is not ready after 30 seconds"
        exit 1
    fi
    echo "  Waiting... ($timeout seconds remaining)"
    sleep 1
done
echo "✅ Database is ready!"

# Apply database schemas
echo ""
echo "📄 Applying database schemas..."
schema_files=(
    "packages/database/schemas/001_tenants.sql"
    "packages/database/schemas/002_users.sql"
    "packages/database/schemas/003_actors.sql"
    "packages/database/schemas/004_detections.sql"
    "packages/database/schemas/005_intelligence.sql"
)

for schema_file in "${schema_files[@]}"; do
    if [ -f "$schema_file" ]; then
        echo "  Applying: $schema_file"
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$schema_file" -q
        echo "  ✅ Applied: $schema_file"
    else
        echo "  ⚠️ Schema file not found: $schema_file"
    fi
done

# Apply seed data if available
echo ""
echo "🌱 Applying seed data..."
seed_files=(
    "packages/database/seeds/mitre_attack.sql"
)

for seed_file in "${seed_files[@]}"; do
    if [ -f "$seed_file" ]; then
        echo "  Applying: $seed_file"
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$seed_file" -q
        echo "  ✅ Applied: $seed_file"
    else
        echo "  ℹ️ Seed file not found: $seed_file (skipping)"
    fi
done

# Verify database structure
echo ""
echo "🔍 Verifying database structure..."
table_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | xargs)

echo "  Tables created: $table_count"

if [ "$table_count" -ge 5 ]; then
    echo "  ✅ Database structure looks good!"
else
    echo "  ⚠️ Expected at least 5 tables, but found $table_count"
fi

# Test basic functionality
echo ""
echo "🧪 Testing basic functionality..."

# Test tenant creation
tenant_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM tenants;" | xargs)
echo "  Default tenants: $tenant_count"

# Test user creation
user_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM users;" | xargs)
echo "  Default users: $user_count"

if [ "$tenant_count" -ge 1 ] && [ "$user_count" -ge 1 ]; then
    echo "  ✅ Basic functionality test passed!"
else
    echo "  ❌ Basic functionality test failed"
    exit 1
fi

echo ""
echo "🎉 Database initialization completed successfully!"
echo ""
echo "📊 Database Summary:"
echo "  • Tenants: $tenant_count"
echo "  • Users: $user_count"
echo "  • Total tables: $table_count"
echo ""
echo "🔗 Connection details:"
echo "  • URL: postgresql://$DB_USER:***@$DB_HOST:$DB_PORT/$DB_NAME"
echo "  • Admin user: admin@countermeasure.dev"
echo "  • Admin password: admin123"