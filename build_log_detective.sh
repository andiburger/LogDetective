#!/bin/bash

# Build script for LogDetective Docker image

IMAGE_NAME="log_detective"
TAG="pi5"
PLATFORM="linux/arm64"  # change to linux/arm/v7 for 32-bit Pi OS

echo "Building Docker image: ${IMAGE_NAME}:${TAG} for platform ${PLATFORM}"

docker build --platform ${PLATFORM} -t ${IMAGE_NAME}:${TAG} .

if [ $? -eq 0 ]; then
  echo "✅ Build completed successfully."
else
  echo "❌ Build failed."
  exit 1
fi