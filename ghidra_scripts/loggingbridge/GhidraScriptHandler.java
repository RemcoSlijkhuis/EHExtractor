package loggingbridge;

import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;

import ghidra.app.script.GhidraScript;

public class GhidraScriptHandler extends Handler {

	private GhidraScript script = null;
	
	public GhidraScriptHandler(GhidraScript script) {
		this.script = script;
	}

	@Override
	public void publish(LogRecord record) {
		if (isLoggable(record)) {
			String msg = getFormatter().format(record);
			while (msg.endsWith(System.lineSeparator()) || msg.endsWith("\r"))
				msg = msg.substring(0, msg.length()-1);
			script.println(msg);
		}
	}
	
	@Override
	public void setFormatter(Formatter newFormatter) throws SecurityException {
	    super.setFormatter(newFormatter != null ? newFormatter : new SimpleFormatter());
	}

	@Override
	public void flush() {
	}

	@Override
	public void close() throws SecurityException {
	}

}
