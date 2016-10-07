package com.hanlon.netapi;

import android.util.Log;

public class Ping {

	public static final String TAG = "Ping";
	
	private long mCtx = 0 ; 
	public void start(){
		if( mCtx == 0 ){
			mCtx = start_ping();
		}else{
			Log.d(TAG,"running! please stop before start again");
		}
	}
	public void stop(){
		if( mCtx > 0 ) {
			stop_ping(mCtx);
			mCtx = 0 ;
		}else{
			Log.d(TAG,"already stop! please start again");
		}
	}
	
	native public long start_ping();
	native public void stop_ping(long ctx);
	
	static{
		System.loadLibrary("netsocket");
	}
}
