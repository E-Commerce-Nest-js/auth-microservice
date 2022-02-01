/* eslint-disable @typescript-eslint/explicit-function-return-type */
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ModelType } from '@typegoose/typegoose/lib/types';
import { compare, genSalt, hash } from 'bcryptjs';
import { InjectModel } from 'nestjs-typegoose';
import { UserModel } from './user.model';
import { Roles } from '../common/types/roles.type';
import { SignUpDto } from './dto/signup.dto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(UserModel) private readonly userModel: ModelType<UserModel>,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) {
        this.createAdminIfNotExists()
            .then((data) =>
                data ? console.log('Admin created') : console.log('Admin already exists'),
            )
            .catch((err) => console.log('Error: Admin is not created -> ', err));
    }

    async createAdminIfNotExists() {
        const adminDto = {
            email: this.configService.get('ADMIN_EMAIL') || 'admin@mail.com',
            password: this.configService.get('ADMIN_PASSWORD') || 'admin',
            username: this.configService.get('ADMIN_USERNAME') || 'admin',
            role: Roles.Admin,
        };
        const isAdmin = await this.userModel.findOne({ username: adminDto.username }).exec();
        if (isAdmin) {
            return null;
        }
        const salt = await genSalt(10);
        const newAdmin = new this.userModel({
            email: adminDto.email,
            passwordHash: await hash(adminDto.password, salt),
            username: adminDto.username,
            role: adminDto.role,
        });
        return newAdmin.save();
    }

    async getUserByEmail(email: string) {
        return this.userModel.findOne({ email }).exec();
    }

    async getUserById(id: string) {
        return this.userModel.findOne({ _id: id }).exec();
    }

    async getUsersList() {
        return this.userModel.find({}, { passwordHash: 0, refresh_token: 0 }).exec();
    }

    async createUser(dto: SignUpDto) {
        const salt = await genSalt(10);
        const newUser = new this.userModel({
            email: dto.email,
            passwordHash: await hash(dto.password, salt),
            username: dto.username,
            role: Roles.User,
        });
        return newUser.save();
    }

    async validateUser(email: string, password: string) {
        const user = await this.getUserByEmail(email);
        if (!user) {
            return null;
        }
        const isCorrectPassword = await compare(password, user.passwordHash);
        if (!isCorrectPassword) {
            return null;
        }
        return user;
    }

    async getAccessToken(user: UserModel) {
        const payload = { email: user.email, id: user._id, role: user.role };
        return {
            access_token: await this.jwtService.signAsync(payload),
        };
    }

    async getCookieWithRefreshToken(id: string) {
        const payload = { id };
        const token = await this.jwtService.signAsync(payload, {
            expiresIn: this.configService.get('JWT_REFRESH_EXPIRATION_TIME'),
        });
        const cookie = `Refresh=${token}; HttpOnly; Path=/; Max-Age=${
            this.configService.get('JWT_REFRESH_EXPIRATION_TIME') / 1000
        }`;
        return { cookie, token };
    }

    async getUserIfRefreshTokenMatches(refreshToken: string, userId: string) {
        const user = await this.getUserById(userId);
        const isRefreshTokenMatching = await compare(refreshToken, user.refresh_token);
        if (isRefreshTokenMatching) {
            return user;
        }
    }

    async setCurrentRefreshToken(refreshToken: string, userId: string) {
        const refreshTokenHash = await hash(refreshToken, 10);
        this.userModel.findByIdAndUpdate(userId, { refresh_token: refreshTokenHash }).exec();
    }

    async setRole(userId: string, newRole: string) {
        return await this.userModel
            .findByIdAndUpdate(userId, { role: newRole }, { new: true })
            .exec();
    }

    async removeRefreshToken(userId: string) {
        this.userModel.findByIdAndUpdate(userId, { refresh_token: null }).exec();
    }

    getCleanCookieForRefreshToken() {
        return 'Refresh=; HttpOnly; Path=/; Max-Age=0';
    }
}
