<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

// Route::group([

//     'middleware' => 'api',
//     'namespace' => 'App\Http\Controllers',
//     'prefix' => 'auth'
    
//     ], function ($router) {
    
//     Route::post('login', 'AuthController@login');
//     Route::post('logout', 'AuthController@logout');
//     Route::post('refresh', 'AuthController@refresh');
//     Route::post('me', 'AuthController@me');
    
// });
Route::group([
    'namespace' => 'App\Http\Controllers'
], function($router){
    Route::post('login', 'AuthController@login')->name('login');
    Route::post('register', 'AuthController@register');
});

Route::group([
    'middleware' => 'auth.jwt',
    'namespace' => 'App\Http\Controllers'
], function(){
    Route::get("logout", "AuthController@logout");
});