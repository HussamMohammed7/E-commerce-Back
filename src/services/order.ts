import Order from "../models/order";
import {Filter, OrderStatus, ProductInsideOrder, SortOptions} from "../types/orders";
export const  servicesGetOrders=async(filter:Filter,sortOptions:SortOptions,page:number ,perPage:number)=>{
    return  Order.find(filter)
         .sort(sortOptions.sort)
         .skip((page - 1) * perPage)
         .limit(perPage)
}
export const servicesGetOrder=async (orderId:string)=>{
    return await Order.findById(orderId).populate('products.product').populate('userId').exec()
}
export const servicesCreateOrder=  (userId:string,products:ProductInsideOrder[],total:number)=>{
    const order=new Order({
        userId,
        products,
        total
    })
    return order.save()
}
export const servicesDeleteOrder=async (orderId:string)=>{
   return await Order.deleteOne({_id:orderId}).exec()
}
export const servicesCountOrders= async (filter:Filter)=>{
   return await  Order.countDocuments(filter)
}
export const serviceUpdateOrder=async (orderId:string,status:OrderStatus)=>{
    return await Order.findByIdAndUpdate(orderId, { status:status },{new: true}).exec()

}