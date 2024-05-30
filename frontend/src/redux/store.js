import { configureStore , combineReducers } from '@reduxjs/toolkit'
import itemsReducer from './slice/itemsSlice'
import asynchronousReducer from './slice/asynchronousCall'


// Combine reducers
    const rootReducer = combineReducers({
        items: itemsReducer,
        data: asynchronousReducer
    });

// Configure the Redux store
    const store = configureStore({
        reducer: rootReducer
    });

  export default store;;  

