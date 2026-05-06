package com.poc.controlsleak;

import android.service.controls.ControlsProviderService;
import android.service.controls.Control;
import android.service.controls.actions.ControlAction;

import java.util.List;
import java.util.concurrent.Flow;
import java.util.function.Consumer;

/**
 * Dummy ControlsProviderService to make our ComponentName valid for the
 * ControlsRequestReceiver. This service doesn't need to do anything real —
 * its existence just makes the ComponentName resolve correctly.
 */
public class DummyControlsService extends ControlsProviderService {

    @Override
    public Flow.Publisher<Control> createPublisherForAllAvailable() {
        return subscriber -> {
            subscriber.onComplete();
        };
    }

    @Override
    public Flow.Publisher<Control> createPublisherFor(List<String> controlIds) {
        return subscriber -> {
            subscriber.onComplete();
        };
    }

    @Override
    public void performControlAction(String controlId, ControlAction action,
            Consumer<Integer> consumer) {
        consumer.accept(ControlAction.RESPONSE_OK);
    }
}
