FROM node:18-alpine

# Cài đặt bash để có thể chui vào container debug nếu cần
RUN apk add --no-cache bash

WORKDIR /usr/src/app

# Copy package files trước để tận dụng cache layer của Docker
COPY package*.json ./

# Cài đặt dependencies
RUN npm install

# Copy toàn bộ source code
COPY . .

# Build dự án
RUN npm run build

# Expose port
EXPOSE 3000

# Chạy app ở chế độ development
CMD ["npm", "run", "start:dev"]
