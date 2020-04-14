package sampleLoyalty;

import javacard.framework.Shareable;

public interface JavaLoyaltyInterface extends Shareable {
	void grantPoints (short points);
	
}

