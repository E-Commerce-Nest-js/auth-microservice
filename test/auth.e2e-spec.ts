import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { Connection, disconnect } from 'mongoose';
import { getConnectionToken, TypegooseModule } from 'nestjs-typegoose';
import * as cookieParser from 'cookie-parser';
import { SignUpDto } from 'src/auth/dto/signup.dto';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Roles } from '../src/common/types/roles.type';
import { AuthService } from '../src/auth/auth.service';
import { AuthModule } from '../src/auth/auth.module';
import { getMongoConfig } from '../src/configs/mongo.config';
import { RMQModule } from 'nestjs-rmq';

describe('AuthController (e2e)', () => {
    let app: INestApplication;
    let connection: Connection;
    let configService: ConfigService;
    interface TestUser {
        dto: SignUpDto;
        refreshCookie: string;
        accessToken: string;
    }
    let admin: TestUser;
    let user: TestUser;
    let userId: string;

    beforeAll(async () => {
        const testAppModule: TestingModule = await Test.createTestingModule({
            imports: [
                AuthModule,
                ConfigModule.forRoot(),
                TypegooseModule.forRootAsync({
                    imports: [ConfigModule],
                    inject: [ConfigService],
                    useFactory: getMongoConfig,
                }),
                RMQModule.forTest({}),
            ],
        }).compile();

        app = testAppModule.createNestApplication();
        app.useGlobalPipes(new ValidationPipe());
        app.use(cookieParser());
        await app.init();

        connection = await testAppModule.get(getConnectionToken());
        await connection.dropDatabase();

        configService = await testAppModule.get(ConfigService);
        const authService = testAppModule.get(AuthService);
        await authService.createAdminIfNotExists();

        const adminEmail = configService.get('ADMIN_EMAIL') || 'admin@mail.com';
        const adminPassword = configService.get('ADMIN_PASSWORD') || 'admin';

        admin = {
            dto: {
                email: adminEmail,
                password: adminPassword,
                username: 'admin',
            },
            refreshCookie: undefined,
            accessToken: undefined,
        };

        user = {
            dto: {
                email: 'user@mail.com',
                password: 'userPassword',
                username: 'userName',
            },
            refreshCookie: undefined,
            accessToken: undefined,
        };
    });

    afterAll(() => {
        disconnect();
    });

    describe('/auth/sign-up (POST)', () => {
        test('(SUCCESS) should return 201 and created user', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-up')
                .send(user.dto);

            userId = response.body._id;

            expect(response.statusCode).toBe(201);
            expect(response.body).toEqual(
                expect.objectContaining({
                    _id: expect.any(String),
                    email: expect.stringContaining(user.dto.email),
                    role: expect.stringContaining(Roles.User),
                    username: expect.stringContaining(user.dto.username),
                }),
            );
        });

        test('(VALIDATION) should return 400 with message: ["password must be a string", "password should not be empty"]', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-up')
                .send({ ...user.dto, password: undefined });

            expect(response.statusCode).toBe(400);
            expect(response.body.message).toEqual([
                'password must be a string',
                'password should not be empty',
            ]);
        });

        test('(VALIDATION) should return 400 with message: ["username must be a string", "username should not be empty"]', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-up')
                .send({ ...user.dto, username: undefined });

            expect(response.statusCode).toBe(400);
            expect(response.body.message).toEqual([
                'username must be a string',
                'username should not be empty',
            ]);
        });

        test('(VALIDATION) should return 400 with message: ["email must be a string", "email must be an email", "email should not be empty"]', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-up')
                .send({ ...user.dto, email: undefined });

            expect(response.statusCode).toBe(400);
            expect(response.body.message).toEqual([
                'email must be a string',
                'email must be an email',
                'email should not be empty',
            ]);
        });

        test('(ERROR) should return 422 because "user already exists"', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-up')
                .send(user.dto);

            expect(response.statusCode).toBe(422);
        });
    });

    describe('/api/auth/sign-in (POST)', () => {
        test('(SUCCESS) should return 200 with access_token, refresh -> cookie', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-in')
                .send(user.dto);

            const cookies = response.get('Set-Cookie');
            user.refreshCookie = cookies[0];
            user.accessToken = response.body.access_token;

            expect(response.statusCode).toBe(200);
            expect.stringContaining(user.refreshCookie);
            expect.stringContaining(user.accessToken);
        });

        test('(SUCCESS) [by Admin] should return 200 with access_token, refresh -> cookie', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-in')
                .send(admin.dto);

            const cookies = response.get('Set-Cookie');
            admin.refreshCookie = cookies[0];
            admin.accessToken = response.body.access_token;

            expect(response.statusCode).toBe(200);
            expect.stringContaining(admin.refreshCookie);
            expect.stringContaining(admin.accessToken);
        });

        test('(VALIDATION) should return 400 with message: ["password must be a string", "password should not be empty"]', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-in')
                .send({ ...user.dto, password: undefined });

            expect(response.statusCode).toBe(400);
            expect(response.body.message).toEqual([
                'password must be a string',
                'password should not be empty',
            ]);
        });

        test('(VALIDATION) should return 400 with message: ["email must be a string", "email must be an email", "email should not be empty"]', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-in')
                .send({ ...user.dto, email: undefined });

            expect(response.statusCode).toBe(400);
            expect(response.body.message).toEqual([
                'email must be a string',
                'email must be an email',
                'email should not be empty',
            ]);
        });

        test('(ERROR) should return 401 "invalid login or password" when invalid email', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-in')
                .send({ ...user.dto, email: 'wrong@wrong.com' });

            expect(response.statusCode).toBe(401);
        });

        test('(ERROR) should return 401 "invalid login or password" when invalid password', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-in')
                .send({ ...user.dto, password: 'wrongpassword' });

            expect(response.statusCode).toBe(401);
        });
    });

    describe('/api/auth/refresh (POST)', () => {
        test('(SUCCESS) should refresh', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/refresh')
                .set('Cookie', user.refreshCookie);

            const cookies = response.get('Set-Cookie');
            user.refreshCookie = cookies[0];
            user.accessToken = response.body.access_token;

            expect(response.statusCode).toBe(201);
            expect.stringMatching(user.refreshCookie);
            expect.stringContaining(user.accessToken);
        });

        test('(ERROR) should return 401 because cookie with refresh_token is invalid', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/refresh')
                .set('Cookie', 'Refresh=asdf');

            expect(response.statusCode).toBe(401);
        });
    });

    describe('/api/auth/sign-out (POST)', () => {
        test('(SUCCESS) should return 200 and clean Refresh in cookies => sign-in again', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-out')
                .set('Authorization', `Bearer ${user.accessToken}`);

            const cookies = response.get('Set-Cookie');
            user.refreshCookie = cookies[0];

            expect(response.statusCode).toBe(200);
            expect(cookies[0]).toBe('Refresh=; HttpOnly; Path=/; Max-Age=0');

            // user sign-in again
            {
                const response = await request(app.getHttpServer())
                    .post('/auth/sign-in')
                    .send(user.dto);

                const cookies = response.get('Set-Cookie');
                user.refreshCookie = cookies[0];
                user.accessToken = response.body.access_token;

                expect(response.statusCode).toBe(200);
                expect.stringContaining(user.refreshCookie);
                expect.stringContaining(user.accessToken);
            }
        });

        test('(ERROR) should return 401 because access_token is invalid', async () => {
            const response = await request(app.getHttpServer())
                .post('/auth/sign-out')
                .set('Authorization', `Bearer INVALID.ACCESS.TOKEN`);

            expect(response.statusCode).toBe(401);
        });
    });

    describe('/api/auth/iam (GET)', () => {
        test('(SUCCESS) should return 200 with user information', async () => {
            const response = await request(app.getHttpServer())
                .get('/auth/iam')
                .set('Authorization', `Bearer ${user.accessToken}`);

            expect(response.statusCode).toBe(200);
            expect(response.body).toEqual(
                expect.objectContaining({
                    _id: expect.any(String),
                    email: expect.stringContaining(user.dto.email),
                    role: expect.stringContaining(Roles.User),
                    username: expect.stringContaining(user.dto.username),
                }),
            );
        });

        test('(ERROR) should return 401 because access_token is invalid', async () => {
            const response = await request(app.getHttpServer())
                .get('/auth/iam')
                .set('Authorization', `Bearer INVALID.ACCESS.TOKEN`);

            expect(response.statusCode).toBe(401);
        });
    });

    describe('/api/auth/list (GET)', () => {
        test('(SUCCESS) [by Admin] should return 200 with list of users', async () => {
            const response = await request(app.getHttpServer())
                .get('/auth/list')
                .set('Authorization', `Bearer ${admin.accessToken}`);

            expect(response.statusCode).toBe(200);
            expect(response.body).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        _id: expect.any(String),
                        email: expect.any(String),
                        role: expect.any(String),
                        username: expect.any(String),
                    }),
                ]),
            );
        });

        test('(ERROR) [by User] should return 403 because route only for Admin', async () => {
            const response = await request(app.getHttpServer())
                .get('/auth/list')
                .set('Authorization', `Bearer ${user.accessToken}`);

            expect(response.statusCode).toBe(403);
        });

        test('(ERROR) should return 401 because access_token invalid', async () => {
            const response = await request(app.getHttpServer())
                .get('/auth/list')
                .set('Authorization', `Bearer INVALID.ACCESS.TOKEN`);

            expect(response.statusCode).toBe(401);
        });
    });

    describe('/api/auth/role (PATCH)', () => {
        test('(SUCCESS) [by Admin]  should return 200 and new user data', async () => {
            const response = await request(app.getHttpServer())
                .patch('/auth/role')
                .set('Authorization', `Bearer ${admin.accessToken}`)
                .send({
                    userId: userId,
                    role: Roles.User,
                });

            expect(response.statusCode).toBe(200);
            expect(response.body).toEqual(
                expect.objectContaining({
                    _id: expect.any(String),
                    email: expect.stringContaining(user.dto.email),
                    role: expect.stringContaining(Roles.User),
                    username: expect.stringContaining(user.dto.username),
                }),
            );
        });

        test('(VALIDATION) should return 400 with message: ["userId must be a mongodb id", "userId must be a string", "userId should not be empty"]', async () => {
            const response = await request(app.getHttpServer())
                .patch('/auth/role')
                .set('Authorization', `Bearer ${admin.accessToken}`)
                .send({
                    userId: undefined,
                    role: Roles.User,
                });

            expect(response.statusCode).toBe(400);
            expect(response.body.message).toEqual([
                'userId must be a mongodb id',
                'userId must be a string',
                'userId should not be empty',
            ]);
        });

        test('(VALIDATION) should return 400 with message: ["role must be a string", "role must be a valid enum value", "role should not be empty",]', async () => {
            const response = await request(app.getHttpServer())
                .patch('/auth/role')
                .set('Authorization', `Bearer ${admin.accessToken}`)
                .send({
                    userId,
                    role: undefined,
                });

            expect(response.statusCode).toBe(400);
            expect(response.body.message).toEqual([
                'role must be a string',
                'role must be a valid enum value',
                'role should not be empty',
            ]);
        });

        test('(ERROR) [by User] should return 403 because route only for Admin', async () => {
            const response = await request(app.getHttpServer())
                .patch('/auth/role')
                .set('Authorization', `Bearer ${user.accessToken}`)
                .send({
                    userId: userId,
                    role: Roles.User,
                });

            expect(response.statusCode).toBe(403);
        });
    });
});
