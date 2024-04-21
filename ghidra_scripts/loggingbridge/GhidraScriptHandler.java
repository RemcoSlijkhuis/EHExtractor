package loggingbridge;

import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;

import ghidra.app.script.GhidraScript;

/**
 * Custom log handler that directs log output to the Ghidra script console.
 */
public class GhidraScriptHandler extends Handler {

	private GhidraScript script = null;
	
	/**
     * Creates a GhidraScriptHandler with the specified GhidraScript instance.
     * @param script The GhidraScript instance to use for outputting log messages.
     */
	public GhidraScriptHandler(GhidraScript script) {
		this.script = script;
	}

	/**
     * Formats and outputs a LogRecord to the Ghidra script console, if it should be logged.
     * @param record The log record to be published.
     */
	@Override
	public void publish(LogRecord record) {
		if (isLoggable(record)) {
			String msg = getFormatter().format(record);
			while (msg.endsWith(System.lineSeparator()) || msg.endsWith("\r"))
				msg = msg.substring(0, msg.length()-1);
			script.println(msg);
		}
	}
	
	/**
     * Sets the Formatter for this handler. SimpleFormatter will be used if newFormatter is null.
     * @param newFormatter The Formatter to use, or null (SimpleFormatter will be used, then).
     */
	@Override
	public void setFormatter(Formatter newFormatter) throws SecurityException {
	    super.setFormatter(newFormatter != null ? newFormatter : new SimpleFormatter());
	}

	/**
     * Does nothing as this handler does not need to explicitly flush any data.
     */
	@Override
	public void flush() {
	}

	/**
     * Does nothing as this handler does not hold any resources that need to be closed explicitly.
     */
	@Override
	public void close() throws SecurityException {
	}

}
