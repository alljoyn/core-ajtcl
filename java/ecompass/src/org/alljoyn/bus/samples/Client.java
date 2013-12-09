/*
 * Copyright (c) 2013, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package org.alljoyn.bus.samples;

import com.sun.j3d.utils.universe.SimpleUniverse;

import com.sun.j3d.loaders.Loader;
import com.sun.j3d.loaders.Scene;
import org.web3d.j3d.loaders.X3DLoader;

import javax.media.j3d.BranchGroup;
import javax.media.j3d.TransformGroup;
import javax.media.j3d.Transform3D;
import javax.media.j3d.AmbientLight;
import javax.media.j3d.DirectionalLight;
import javax.media.j3d.BoundingSphere;

import javax.vecmath.Vector3d;
import javax.vecmath.Vector3f;
import javax.vecmath.Point3d;
import javax.vecmath.Color3f;

import java.lang.Math;

import org.alljoyn.bus.BusAttachment;
import org.alljoyn.bus.Status;
import org.alljoyn.bus.annotation.BusSignalHandler;

public class Client {
	static { 
		System.loadLibrary("alljoyn_java");
	}

	static double mPitch = 0f;
	static double mRoll = 0f;
	
	public static class SampleSignalHandler  {
		@BusSignalHandler(iface="org.alljoyn.bus.samples.ecompass", signal="NewRawAccelerationAndMagneticFieldValues")
		public void NewRawAccelerationAndMagneticFieldValues(short Ax, short Ay, short Az, short Mx, short My, short Mz) {		
			/*
			 * Normalize the components of the acceleration to units of little g.
			 */
			double ax = (double)Ax / 16384f;
			double ay = (double)Ay / 16384f;
			double az = (double)Az / 16384f;
			
			/*
			 * Pitch and Roll estimation are a little more tricky than one may
			 * think.  There is a good application note from Freescale
			 * Semiconductor that discusses the problem in mind-numbing detail
			 * if you are interested:
			 * 
			 *  cache.freescale.com/files/sensors/doc/app_note/AN3461.pdf
			 *
			 * We are doing to use the so-called aerospace rotation sequence
			 * which, when solved for phi (roll) and theta (pitch).  Yaw
			 * cannot be found with an accelerometer reading alone.
			 * 
			 * See the application note to decipher the following two LOC.
			 */
			double roll = Math.atan(ay /az);
			double pitch = Math.atan(-ax / Math.sqrt(ay * ay + az * az));
			
			/*
			 * Convert to degrees for those of us who don't think in radians.
			 */
			double rotX = roll * 360 / (2 * Math.PI);
			double rotY = pitch * 360 / (2 * Math.PI);
			
			System.out.println(String.format("New rotations %f, %f", rotX, rotY));
			
			mPitch = pitch;
			mRoll = roll;
		}
	}

	static BusAttachment mBus;
	
	public static void main(String[] args) {
		mBus = new BusAttachment("ecompass", BusAttachment.RemoteMessage.Receive);
		
		Status status = mBus.connect();
		if (status != Status.OK) {
			System.exit(0);
		}
		
		SampleSignalHandler mySignalHandler = new SampleSignalHandler();
		status = mBus.registerSignalHandlers(mySignalHandler);
		if (status != Status.OK) {
			System.exit(0);
		}
				
		/*
		 * Create the root of the scene graph.
		 */
		BranchGroup root = new BranchGroup();
		
		/*
		 * Create a transform group and give it the capability to be changed
		 * at runtime.
		 */
		TransformGroup tg = new TransformGroup();
		tg.setCapability(TransformGroup.ALLOW_TRANSFORM_WRITE);
		
		/*
		 * Create a simple shape and add it to the scene graph under its parent
		 * transform group.
		 */
//		ColorCube shape = new ColorCube(0.5);
//		tg.addChild(shape);
		
		/*
		 * Instead of creating a simple shape, we load a file describing a
		 * complicated object and at it to the transform group.
		 */
		Loader loader = new X3DLoader();
		Scene scene = null;
		try {
			scene = loader.load("/git/ajlite/java/ecompass/F18.wrl");
		} catch (Exception e) {
			System.out.println("Can't load WRL file");
		}	
		tg.addChild(scene.getSceneGroup());
		
        Transform3D t3dScene = new Transform3D();
        t3dScene.setTranslation(new Vector3d(0.0, 0.0, 0.0));
		tg.setTransform(t3dScene);
		
		/*
		 * Add the transform group with its associated shild shape to the scene
		 * graph.
		 */
		root.addChild(tg);
		
		/*
		 * Add some ambient lighting so we can see the overall scene.  Make it
		 * a uniform gray color and set its influence to a large bounding sphere
		 * that should cover most reasonable scenes.
		 */
		BoundingSphere ambientBounds = new BoundingSphere(new Point3d(0.0, 0.0, 0.0), 1000.0);
		Color3f ambientColor = new Color3f(0.5f, 0.5f, 0.5f);
		AmbientLight ambientLight = new AmbientLight(ambientColor);
		ambientLight.setInfluencingBounds(ambientBounds);
		root.addChild(ambientLight);

		/*
		 * Add some directional lighting coming down at an angle from above to
		 * simulate the sun.  Make it a vaguely yellow color so the plane looks
		 * natural.
		 */
		Color3f directionalColor = new Color3f(1.0f, 1.0f, 0.9f);
		BoundingSphere directionalBounds = new BoundingSphere(new Point3d(0.0, 100.0, 100.0), 200.0);
		Vector3f direction = new Vector3f(0.0f, -1.0f, -1.0f);
		DirectionalLight theSun = new DirectionalLight(directionalColor, direction);
		theSun.setInfluencingBounds(directionalBounds);
		root.addChild(theSun);

		/*
		 * Create a simple universe for our scene graph to live in.
		 */
		SimpleUniverse universe = new SimpleUniverse();
		
		/*
		 * Move the view platform around so we are looking at the object from
		 * the desired distance and angle.  Increasing the X value moves the
		 * viewing platform to the right, and so the scene appears to move to
		 * the left in the window.  Increasing the Y value moves the viewing
		 * platform up and so the scene appears to move down.  Increasing the
		 * X value moves the viewing platform back along the Z-axis so that
		 * the object may be shown in its entirety.
		 */
        Transform3D t3dView = new Transform3D();
        t3dView.setTranslation(new Vector3d(0.0, 0.0, 30.0));
		universe.getViewingPlatform().getViewPlatformTransform().setTransform(t3dView);

		/*
		 *  Add the scene graph to the universe.
		 */
		universe.addBranchGraph(root);
			
		Transform3D t3dRoll = new Transform3D();
		Transform3D t3dPitch = new Transform3D();
		Transform3D t3dScale = new Transform3D();
		
		/*
		 * Nothing but the most simple stuff here.  We happen to know that
		 * the accelerometer service is running at a sample rate of 25
		 * samples per second, so we just poll for changes at that rate.
		 * 
		 * This should be good enough for an entertaining user experience.
		 */
		double pitch = 0.0;
		double roll = 0.0;
		while(true) {
			if (mPitch != pitch || mRoll != roll ) {
				pitch = mPitch;
				roll = mRoll;
				t3dRoll.rotX(-roll);
				t3dPitch.rotZ(pitch);
				t3dRoll.mul(t3dPitch);
				t3dRoll.mul(t3dScale);
				tg.setTransform(t3dRoll);
			}
			
			try {
				Thread.sleep(40);
			} catch (InterruptedException e) {
				System.out.println("Program interupted");
			}
		}
	}
}
