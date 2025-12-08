export declare class TestController {
    healthCheck(): {
        status: string;
        timestamp: Date;
        service: string;
        version: string;
    };
    protectedRoute(user: any): {
        message: string;
        user: {
            id: any;
            username: any;
            roles: any;
        };
    };
    adminOnly(user: any): {
        message: string;
        user: {
            id: any;
            username: any;
        };
    };
    userManagement(user: any): {
        message: string;
        user: {
            id: any;
            username: any;
        };
    };
}
