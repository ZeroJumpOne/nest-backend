import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';

import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot(),
    MongooseModule.forRoot(process.env.MONGO_URI),

    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {

  constructor() {
    // console.log(process.env); 
    // console.log(process.env.MONGO_URI);
  }
}
