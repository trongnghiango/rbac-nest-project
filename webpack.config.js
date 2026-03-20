const nodeExternals = require('webpack-node-externals');
const webpack = require('webpack');

module.exports = function (options, webpackInstance) {
    return {
        ...options,
        // 1. CHỈ ĐỊNH CÁC THƯ VIỆN KHÔNG ĐƯỢC BUNDLE (Native C++ & CLI Tools)
        node: {
            __dirname: false,
            __filename: false,
        },
        externals: [
            // Giữ lại các thư viện Core của NestJS & Node.js
            nodeExternals({
                allowlist: [
                    // Nếu bạn MUỐN bundle một thư viện cụ thể nào đó (vd: lodash), 
                    // hãy đưa nó vào đây. Nếu không, nodeExternals sẽ loại bỏ TẤT CẢ node_modules.
                    // Khuyến nghị cho Backend: Để rỗng mảng này để an toàn nhất.
                ],
            }),
            // Cấu hình thủ công thêm cho chắc chắn (Hardcode):
            'bcrypt',
            'pg',
            'pg-query-stream',

            // 🚀 CÁC THƯ VIỆN XỬ LÝ 3D (Được lấy từ dental.config.ts của bạn)
            // Những tool này chứa các file binary/CLI (bin/obj2gltf.js), 
            // TUYỆT ĐỐI KHÔNG ĐƯỢC bundle vì sẽ làm gãy đường dẫn thực thi.
            'obj2gltf',
            'gltf-pipeline',
            '@gltf-transform/cli',
            '@gltf-transform/core',
            '@gltf-transform/extensions',
            '@gltf-transform/functions',
        ],

        plugins: [
            ...options.plugins,

            // 2. FIX LỖI KINH ĐIỂN CỦA POSTGRESQL (pg)
            // Thư viện 'pg' luôn cố gắng require thư viện C++ 'pg-native' để tăng tốc.
            // Webpack sẽ quăng Warning đỏ chót nếu không tìm thấy. Dòng này giúp tắt cảnh báo đó.
            new webpack.IgnorePlugin({
                resourceRegExp: /^pg-native$/,
            }),

            // Fix cảnh báo của class-validator / class-transformer (nếu có)
            new webpack.IgnorePlugin({
                checkResource(resource) {
                    const lazyImports = ['@nestjs/microservices', '@nestjs/microservices/microservices-module', '@grpc/grpc-js', 'amqp-connection-manager', 'amqplib', 'kafkajs', 'mqtt', 'nats', 'redis'];
                    if (!lazyImports.includes(resource)) {
                        return false;
                    }
                    try {
                        require.resolve(resource);
                    } catch (err) {
                        return true;
                    }
                    return false;
                },
            }),
        ],

        // 3. TỐI ƯU HÓA CHO PRODUCTION
        optimization: {
            ...options.optimization,
            minimize: true, //process.env.NODE_ENV === 'production', // Chỉ làm rối code (Minify) khi build Prod
        },
    };
};
