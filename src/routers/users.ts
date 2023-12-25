import express from 'express'

import ApiError from '../errors/ApiError'
import User from '../models/user'
import { DeleteOneUser, activation, addAddress, addOneUser, deleteAddress, forgotPassword, getAllUsers, getOneUser, login, register, resetPassword, updateUser } from '../controllers/userController'
import { validateForgetUser, validateLoginUser, validateResetPassword, validateUpdateUser, validateUser, validateUserID } from '../middlewares/userValdiation'
import { checkAuth } from '../middlewares/checkAuth'
import { deleteCategory } from '../controllers/categoryController'
const router = express.Router()

//List all Users : work 
router.get('/',checkAuth('admin'), getAllUsers)

//List one user : work 
router.get('/:userId',validateUserID, getOneUser)


//Delete User : work
router.delete('/:userId',checkAuth('admin'),validateUserID, DeleteOneUser)



//Update user : Work
router.put('/:userId',validateUserID,validateUpdateUser, updateUser)




//Add User : work
router.post('/', addOneUser)




router.post('/register',validateUser, register)
router.post('/login',validateLoginUser, login)

router.get('/activateUser/:activationToken',activation)
router.post('/forgot-password',validateForgetUser,forgotPassword )
router.post('/reset-password',validateResetPassword,resetPassword )






//add address : work
router.post('/:userId/address',validateUserID,addAddress)
router.delete('/:userId/address/:addressId',checkAuth('visitor'),validateUserID, deleteAddress)




export default router


