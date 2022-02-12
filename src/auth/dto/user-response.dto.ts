import { ApiProperty } from '@nestjs/swagger';
import { Roles } from '../../common/types/roles.type';

export class UserResponseDto {
    @ApiProperty()
    _id: string;

    @ApiProperty({
        example: 'user@mail.com',
    })
    email: string;

    @ApiProperty({
        example: 'username',
    })
    username: string;

    @ApiProperty({
        example: 'user',
    })
    role: Roles;

    @ApiProperty({
        example: '2022-02-12T14:15:55.670Z',
    })
    createdAt: string;

    @ApiProperty({
        example: '2022-02-12T14:15:55.670Z',
    })
    updatedAt: string;
}
