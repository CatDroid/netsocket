package com.hanlon.netsocket;

import com.hanlon.netapi.Ping;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

public class MainActivity extends Activity {

	private Ping mping ; 
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		 
		((Button)findViewById(R.id.bStartICMPEcho)).setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View arg0) {
				if(mping == null){
					mping = new Ping();
				}
				mping.start();
			}
		});
		((Button)findViewById(R.id.bStopICMPEcho)).setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View arg0) {
				if(mping != null){
					mping.stop();
				}
			}
		});
	}
}
