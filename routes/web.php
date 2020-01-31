<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});


Route::group(['prefix' => 'api',  'middleware' => 'cors'], function () {

    Route::post('/register', 'UserController@register');
    Route::post('/login', 'UserController@login');
    Route::get('/activation/{email}', 'UserController@activation');

    Route::group(['middleware' => 'auth'], function () {
        //User
        Route::get('/users', 'UserController@index');
        Route::get('/users/{id}', 'UserController@detail');
        Route::put('/users/{id}', 'UserController@update');
        Route::delete('/users/{id}', 'UserController@delete');

        //Article
        Route::get('/articles', 'ArticleController@index');
        Route::get('/articles/{id}', 'ArticleController@detail');
        Route::post('/articles', 'ArticleController@store');
        Route::put('/articles/{id}', 'ArticleController@update');
        Route::delete('/articles/{id}', 'ArticleController@delete');

        //Comments
        Route::get('/comments', 'CommentController@index');
        Route::get('/comments/{id}', 'CommentController@detail');
        Route::post('/comments', 'CommentController@store');
        Route::put('/comments/{id}', 'CommentController@update');
        Route::delete('/comments/{id}', 'CommentController@delete');

        //Statistic
        Route::get('/statistic', 'StatisticController@index');
    });
});

