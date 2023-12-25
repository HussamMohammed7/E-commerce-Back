import {Request, Response, NextFunction} from 'express'
import {Filter, SortOptions} from "../types/orders";
import {
    servicesCountOrders,
    servicesCreateOrder,
    servicesDeleteOrder,
    servicesGetOrder,
    servicesGetOrders, serviceUpdateOrder
} from "../services/order";
import {addOrderToUser, servicesGetUser} from "../services/users";
import ApiError from "../errors/ApiError";
import {servicesGetProduct, servicesUpdateProductQuantity} from "../services/product";

export const createOrder = async (req: Request, res: Response, next: NextFunction) => {
    const {userId, products} = req.body
    const findUser = await servicesGetUser(userId)
    console.log('userId: ',userId,'products: ',products)
    let total=0
    let productsAndNewQuantity: { productId: string, newQuantity: number }[] = [];
// check if the user is found
    if (findUser) {
        // check product quantity before creating an order
        for (const item of products) {
            const productInStore: any = await servicesGetProduct(item.product);
            if (productInStore.quantity < item.quantity) {
                next(ApiError.badRequest(`This product (${productInStore.name}) does not have enough quantity`));
                return;
            }
            total=(Number(item.price)*Number(item.quantity))+total
            // console.log('item.product.price',item.price,'item.quantity :', item.quantity,'result : ',item.price*item.quantity)
            const newQuantity = productInStore.quantity - item.quantity;
            productsAndNewQuantity.push({productId: item.product,  newQuantity: newQuantity});
        }
        // update Quantity
        productsAndNewQuantity.forEach(async (item) => await servicesUpdateProductQuantity(item.productId, item.newQuantity))
        //create new  order
        console.log(total,"total 1213")

        const order = await servicesCreateOrder(userId, products,total)
        console.log(order)
        //add this order to user
        await addOrderToUser(userId, order)
        res.status(201).json({
            message: 'create new order and added to user orders',
            order: order,
        })
    } else {
        next(ApiError.badRequest("not found user, wrong user id"))
        return
    }

}

export const getOrders = async (req: Request, res: Response) => {
    const page: number = Number(req.query.page) || 1
    const perPage: number = Number(req.query.perPage) || 3
    const filter: Filter = {}
    const sortOptions: SortOptions = {}
    const status = req.query.date || null
    const sort = req.query.sort || null
    if (status && typeof status === 'string') {
        filter.status = status
    }
    if (sort && typeof sort === 'string') {
        if (sort === 'asc') {
            sortOptions.sort = {purchasedAt: 1}
        }
        if (sort === 'desc') {
            sortOptions.sort = {purchasedAt: -1}
        }
    }
    const orders = await servicesGetOrders(filter, sortOptions, page, perPage)
    const totalItems: number = await servicesCountOrders(filter)
    const totalPage = Math.ceil(totalItems / perPage)

    res.status(200).json({
        message: "order is returned ",
        page,
        perPage,
        totalItems,
        totalPage,
        filter,
        orders: orders
    })
}
export const deleteOrder = async (req: Request, res: Response, next: NextFunction) => {
    const {orderId} = req.params
    const isDelete = await servicesDeleteOrder(orderId)
    if (isDelete['deletedCount'] === 1) {
        res.status(201).json({
            message: 'order is deleted'
        })
    } else {
        next(ApiError.badRequest("not found order id "))
        return
    }
}
export const getOrder = async (req: Request, res: Response, next: NextFunction) => {
    const {orderId} = req.params
    const order = await servicesGetOrder(orderId)
    if (order != null) {
        res.status(200).json({
            message: "order is returned ",
            order: order
        })
    } else {
        next(ApiError.badRequest("order not found"))
        return
    }
}


export const updateOrder = async (req: Request, res: Response, next: NextFunction) => {
    const {orderId} = req.params
    const {status} = req.body
    if (status === "under process" || status === "shopped" || status === "finished" || status === "canceled") {
        const updateOrder = await serviceUpdateOrder(orderId, status)
        console.log(updateOrder)
        if (updateOrder) {

            res.status(200).json({
                message: "order is updated ",
                order: updateOrder
            })
        } else {
            next(ApiError.badRequest("order not found"))
            return
        }
    } else {
        next(ApiError.badRequest("status should be under process, shopped, finished, canceled"))
    }

}