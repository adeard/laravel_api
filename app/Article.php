<?php

namespace App;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Article extends Model
{
    use SoftDeletes;

    public $primaryKey = 'id';
    protected $table = 'articles';
    protected $guarded = ['id'];
    protected $dates =['deleted_at'];

    public function users(){
        return $this->belongsTo('App\User', 'user_id', 'id');
    }

    public function comments(){
        return $this->hasMany('App\Comment', 'article_id', 'id');
    }

    public function latestComment()
    {
        return $this->hasMany('App\Comment')->latest();
    }

}
