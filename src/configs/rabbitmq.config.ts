import { ConfigService } from '@nestjs/config';
import { IRMQServiceOptions } from 'nestjs-rmq';

export const getRmqConfig = async (configService: ConfigService): Promise<IRMQServiceOptions> => {
    return {
        exchangeName: configService.get('RMQ_EXCHANGE_NAME'),
        connections: [
            {
                login: configService.get('RMQ_LOGIN'),
                password: configService.get('RMQ_PASSWORD'),
                host: configService.get('RMQ_HOST'),
            },
        ],
        logMessages: true,
    };
};
