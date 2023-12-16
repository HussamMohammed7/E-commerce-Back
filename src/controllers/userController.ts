import ApiError from '../errors/ApiError'
import {Request,Response,NextFunction} from 'express'
import User from '../models/user'
import crypto from 'crypto'
import bcrypt from 'bcrypt'
import { sendActivationEmail } from '../util/email'
import jwt from 'jsonwebtoken'

type Filter = {

  role? : 'visitor'| 'admin'
}

function generateActivationToken() {
  return crypto.randomBytes(32).toString('hex')
}


export const getAllUsers = async (req:Request, res:Response) => {
  const filter : Filter = {}

    const page = Number(req.query.page)||1
    const perPage = Number(req.query.perPage) || 10
    const role = req.query.role
    console.log(page, perPage)
   


    if(role && typeof role==='string') {
      if(role == 'admin') {
        filter.role = role
      }
      if(role == 'visitor') {
        filter.role = role
      }
    }

    const totalUsers = await User.countDocuments(filter)
    const totalPages = Math.ceil(totalUsers/perPage)

    const users = await User.find(filter)
    .skip((page-1)*perPage)
    .limit(perPage)
    .populate('order')

    res.json({
      page,
      perPage,
      totalUsers,
      totalPages,
      users
      

    }

    )
  }

  // Register user a varivaction

  export const register =  async(req:Request, res:Response,next :NextFunction) => {
    const {first_name, last_name, email, password } = req.validatedUser
    try {
    const userExists = await User.findOne({ email })
    if (userExists) {
      return next(ApiError.badRequest('Email already registered'))
    }
    if (!first_name) {
      next(ApiError.badRequest('First name is required'));
      return;
  }
  
  if (!last_name) {
      next(ApiError.badRequest('Last name is required'));
      return;
  }
  
  if (!email) {
      next(ApiError.badRequest('Email is required'));
      return;
  }
  
  if (!password) {
      next(ApiError.badRequest('Password is required'));
      return;
  }
  
    const activationToken = generateActivationToken()
    // TODO: talk about hashing and Salt
    const hashedPassword = await bcrypt.hash(password, 10)
  
   
    const newUser = new User({first_name, last_name, email, password: hashedPassword,
      activationToken,role : "visitor"});

    
    await newUser.save()
    await sendActivationEmail(email, activationToken)

  
    //TODO: send an email to the user for activation. the email should include the activationToken
  
    res.json({
      msg: 'User registered. Check your email to activate your account!',
      user: newUser,
    })
  } catch (error) {
    console.log('error:', error)
    next(ApiError.badRequest('Something went wrong'))
  }
  }
  
  export const login = async (req:Request, res:Response,next :NextFunction ) => {
    const { email, password } = req.validatedLoginUser
  try {
    const user = await User.findOne({ email }).exec()

    if (!user) {
      return res.status(401).json({
        msg: 'User is not found ',
      })
    }
    // to compare hash password with the login passowrd
    bcrypt.compare(password, user.password, (err, isPassCorrect) => {
      if (err) {
        return res.status(401).json({
          msg: 'Login failed',
        })
      }
      if (isPassCorrect) {
        const token = jwt.sign(
          {
            email: user.email,
            _id: user._id,
            role: user.role,
          },
          process.env.TOKEN_SECRET as string,
          {
            expiresIn: '24h',
          }
        )
        return res.status(200).json({
          msg: 'Login is successful',
          token: token,
          user: user,
        })
      } else {
        return res.status(401).json({
          msg: 'Password is not correct',
        })
      }
    })
  } catch (error) {
    console.log('Error in login', error)
    return res.status(500).json({
      message: 'Cannot find user',
    })
  }
  }

  




  export const activation =  async(req:Request, res:Response,next :NextFunction) => {    const activationToken = req.params.activationToken
    const user = await User.findOne({ activationToken })
  
    if (!user) {
      next(ApiError.badRequest('Invalid activation token'))
      return
    }
  
    user.isActive = true
    user.activationToken = undefined
  
    await user.save()
  
    res.status(200).json({
      msg: 'Account activated successfully',
    })
  }

  export const getOneUser = async (req:Request, res:Response) => {
    const userId = req.params.userId
   const user = await User.findById(userId)
   .populate('order')


  res.status(200).json(user)
  
  } 

   export const DeleteOneUser = async (req:Request, res:Response) => {
    const { userId } = req.params

    const deleteUser =await User.deleteOne({
      _id: userId,
    })
    if(deleteUser['deletedCount'] === 1){
      res.json({
        msg: 'User delete it Successfully done',
      })
    }else{
      res.json({
        msg: 'User not found',
      })
    }
}

export const updateUser = async (req:Request, res:Response) => {
  const first_name = req.body.first_name
  const last_name = req.body.last_name
  const avatar = req.body.avatar
  const userId = req.params.userId
  

  const newUser= await User.findByIdAndUpdate(
    userId,
    {
       first_name: first_name, last_name: last_name ,
        avatar: avatar
      },
    {
      new: true,
    }
  )
  if(!newUser) {
    res.json({
      msg: 'User not found',
      
    })
    return
  }

  res.json({
    user: newUser,
  })
}

export const addOneUser = async (req:Request, res:Response,next :NextFunction) => {

    const { first_name, last_name, email, password, role } = req.body;

    if ( !first_name || !last_name || !email || !password || !role) {
      next(ApiError.badRequest('All user details are required'));
      return;
    }
  
    const newUser = new User({first_name, last_name, email, password,role});
    await newUser.save();
      
      
  
    res.json({
      msg: 'done',
      users: newUser,
    })
}

  
   
  
