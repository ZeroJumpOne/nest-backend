import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } from './dto';

import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) { }


  async create(createUserDto: CreateUserDto): Promise<User> {
    // console.log(createUserDto);

    try {
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData,
      });

      await newUser.save();
      const {password:_, ...user } = newUser.toJSON();
      
      return user;

    } catch (error) {
      console.log(error.code);
      if (error.code = 11000) {
        throw new BadRequestException(`Already exist email ${createUserDto.email}`);
      }
      throw new InternalServerErrorException('Something terrible happend.');
    }
  }

  async register(registerDto: RegisterUserDto): Promise<LoginResponse> {

    const user = await this.create(registerDto);
    
    return {
      user: user,
      token: this.getJWT({ id: user._id}),
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email: email })
    if (!user) {
      throw new UnauthorizedException('Not valid credentials - email');
    }

    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credentials - password');
    }

    console.log(user);    

    const { password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJWT({ id: user.id }),
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async checkToken(token: string): Promise<LoginResponse> {

    const payload = await this.jwtService.verifyAsync<JWTPayload>( token, { secret: process.env.JWT_SEED });

    return;
  }

  async findUserById( id: string ) {

    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();

    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWT(payload: JWTPayload ) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
