import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
    const app = await NestFactory.create(AppModule);
    app.enableCors();
    app.use(cookieParser());
    app.useGlobalPipes(new ValidationPipe());
    app.setGlobalPrefix('api');

    const config = new DocumentBuilder()
        .setTitle('Auth microservice')
        .setDescription('The Auth')
        .setVersion('1.0')
        .addTag('Auth')
        .addBearerAuth()
        .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/auth/docs', app, document);

    await app.listen(3000);
}
bootstrap();
