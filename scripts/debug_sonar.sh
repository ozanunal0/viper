#!/bin/bash
# Debug script for SonarQube configuration

echo "🔍 SonarQube Configuration Debug"
echo "================================"

# Check if sonar-project.properties exists
if [ -f "sonar-project.properties" ]; then
    echo "✅ sonar-project.properties found"
    echo "📋 Project configuration:"
    grep -E "^sonar\.(projectKey|projectName|organization)" sonar-project.properties || echo "⚠️  Missing project identification"
else
    echo "❌ sonar-project.properties not found"
fi

# Check environment variables
echo ""
echo "🔧 Environment Variables:"
echo "SONAR_TOKEN: ${SONAR_TOKEN:+SET}"
echo "SONAR_HOST_URL: ${SONAR_HOST_URL:-NOT_SET}"
echo "SONAR_ORGANIZATION: ${SONAR_ORGANIZATION:-NOT_SET}"

# Check if coverage file exists
echo ""
echo "📊 Coverage Report:"
if [ -f "coverage.xml" ]; then
    echo "✅ coverage.xml found"
    echo "📏 Coverage file size: $(wc -c < coverage.xml) bytes"
else
    echo "❌ coverage.xml not found - run tests with coverage first"
    echo "💡 Run: pytest --cov=src --cov-report=xml"
fi

# Check source directory
echo ""
echo "📁 Source Directory:"
if [ -d "src" ]; then
    echo "✅ src/ directory found"
    echo "📊 Python files in src/: $(find src -name "*.py" | wc -l)"
else
    echo "❌ src/ directory not found"
fi

# Check test directory
echo ""
echo "🧪 Test Directory:"
if [ -d "tests" ]; then
    echo "✅ tests/ directory found"
    echo "📊 Test files: $(find tests -name "test_*.py" | wc -l)"
else
    echo "❌ tests/ directory not found"
fi

echo ""
echo "🚀 To run SonarQube scan locally (if you have SonarQube server):"
echo "sonar-scanner -Dsonar.login=\$SONAR_TOKEN"

echo ""
echo "📝 Common Issues:"
echo "1. Ensure SONAR_TOKEN has project permissions"
echo "2. Verify sonar.projectKey matches your SonarQube project"
echo "3. Check sonar.organization matches your SonarQube organization"
echo "4. Ensure coverage.xml is generated before SonarQube scan"
