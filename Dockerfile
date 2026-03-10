FROM node:22-bookworm-slim

# Cài đặt công cụ hệ thống
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./

# Cài đặt toàn bộ dependencies bao gồm cả devDependencies (để có drizzle-kit)
RUN npm install

COPY . .

# Build NestJS
RUN npm run build

# Tạo thư mục upload
RUN mkdir -p uploads/dental/temp uploads/dental/converted && chmod -R 777 uploads

EXPOSE 8080

# Chạy lệnh push trước khi khởi động app
# Chúng ta dùng sh -c để gộp nhiều lệnh
CMD sh -c "npx drizzle-kit push && npm run start:prod"