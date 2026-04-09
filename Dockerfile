# Use Node.js with Python support
FROM node:20-slim

# Install Python and dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy package files and install Node dependencies
COPY package*.json ./
RUN npm install

# Copy AI engine requirements and install Python dependencies
# (In a real scenario, we'd have a requirements.txt)
RUN pip3 install --no-cache-dir --break-system-packages \
    scikit-learn \
    pandas \
    numpy \
    joblib

# Copy the rest of the application
COPY . .

# Ensure native modules are compiled for Linux inside the container
RUN npm rebuild better-sqlite3 --build-from-source

# Build the frontend
RUN npm run build

# Expose the port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
