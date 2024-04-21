package ehextractor;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.python.jline.internal.Log;

/**
 * Class responsible for setting up and managing logging for EHExtractor (both analyzer and script versions).
 * Logging to a file is included by default; additional handlers can be added.
 */
public class Logging {

	String logfilePath = null;
	Level minLogLevel = Level.ALL;
	FileHandler fh = null;
	boolean setupSuccess = false;
	
	private List<Handler> handlers = null;
	
	/**
     * Constructor to initialize logging with a file path and a minimum log level.
     * @param logfilePath The path to the log file.
     * @param minLogLevel The minimum log level to record.
     */
	public Logging(String logfilePath, Level minLogLevel) {
		this.logfilePath = logfilePath;
		this.minLogLevel = minLogLevel;
		handlers = new ArrayList<Handler>();

		setupSuccess = setupLogger();
	}

    /**
     * Constructor to initialize logging with a file path, a minimum log level, and an external handler.
     * @param logfilePath The path to the log file.
     * @param otherHandler The additional log handler.
     * @param minLogLevel The minimum log level to record.
     */
	public Logging(String logfilePath, Handler otherHandler, Level minLogLevel) {
		this.logfilePath = logfilePath;
		this.minLogLevel = minLogLevel;
		handlers = new ArrayList<Handler>();
		handlers.add(otherHandler);

		setupSuccess = setupLogger();
	}

	/**
     * Checks if logging was successfully set up.
     * @return true if successful, otherwise false.
     */
	public boolean isSetupSuccess() {
		return setupSuccess;
	}
	
	/**
     * Closes the FileHandler associated with this logging instance.
     */
	public void close() {
		if (fh != null)
			fh.close();
		fh = null;
	}
	
	/**
     * Sets up the logger with a minimum log level, handlers and formatters.
     * @return true if successful, false otherwise.
     */
	private boolean setupLogger() {
		// First get rid of an annoying ConsoleHandler on a nameless logger
    	// that Ghidra apparently uses to dump horribly-formatted text (in red) at
    	// random places in the Eclipse Console when you use a logger.
    	removeAnnoyingConsoleHandler();

    	var logger = Logger.getLogger("EHExtractor");
    	
    	try {
    	    // Set a specific minimum logging level.
    	    logger.setLevel(minLogLevel);

    	    // When running the script in Ghidra again without having restarted Ghidra, the
    	    // logger will still be around and have handlers attached (even when having made
    	    // changes in Eclipse); we need to clean up these old handlers.
        	removeHandlers(logger);
    	    
    	    /* Configure the logger with handlers and formatters. */
        	// Always output to a file.
    	    fh = new FileHandler(logfilePath, true);
    	    handlers.add(fh);

    	    for (Handler handler : handlers) {
    	    	logger.addHandler(handler);
    	    }

    	    // The initial line should be different (like SimpleFormatter would do it).
    	    var initialLogFormatter = new MyLogFormatterInitial();
    	    for (Handler handler : handlers) {
        	    handler.setFormatter(initialLogFormatter);
    	    }
    	    
    	    // Log the initial message. (Should end up like "Feb 11, 2024 11:27:23 AM EHExtractor".)
    	    logger.log(Level.INFO, "EHExtractor");

    	    // Switch to the normal formatter.
    	    var normalLogFormatter = new MyLogFormatter(true);
    	    for (Handler handler : handlers) {
        	    handler.setFormatter(normalLogFormatter);
    	    }
    	}
    	catch (SecurityException | IOException e) {
    		Log.error("An error occurred while setting up the logger: " + e.getMessage());
    		logger = null;
    		close();
        	return false;
    	}

    	return true;
	}

	/**
     * Removes a default console handler that creates duplicate and randomly inserted logging output lines.
     */
	private static void removeAnnoyingConsoleHandler() {
    	LogManager manager = LogManager.getLogManager();
    	Logger loggr = manager.getLogger("");
    	var handlers = loggr.getHandlers();
	    for (int i = handlers.length-1; i>=0; i--) {
	    	var handler = handlers[i];
	    	if (handler instanceof java.util.logging.ConsoleHandler)
	    		loggr.removeHandler(handler);
	    }
    }

	/**
     * Removes all handlers from the given logger.
     * @param loggr The logger from which to remove all handlers.
     */
	private static void removeHandlers(Logger loggr) {
    	reportRemoveHandlers(loggr, false, true);
    }

	/**
     * Method to report (deprecated) and/or remove all handlers from the given logger.
     * @param loggr The logger to process.
     * @param report Whether or not to report each encountered handler.
     * @param remove Whether or not to remove each encountered handler.
     */
	private static void reportRemoveHandlers(Logger loggr, boolean report, boolean remove) {
	    if (loggr == null)
	    	return;
    	var handlers = loggr.getHandlers();
	    //if (report)
	    //	println("Nr handlers: " + handlers.length);
	    for (int i = handlers.length-1; i>=0; i--) {
	    	var handler = handlers[i];
	    //	if (report)
	    //		println("" + i + ": " + handler);
	    	if (remove)
	    		loggr.removeHandler(handler);
	    }
    }

	/**
	 * Returns the current date and time in the default Java logging timestamp format.
	 * @return A string with the timestamp.
	 */
	private static String getCurrentTimeStamp() {
		// Default Java logging timestamp format (right?).
        SimpleDateFormat sdfDate = new SimpleDateFormat("MMM dd, yyyy HH:mm:ss a");
        Date now = new Date();
        return sdfDate.format(now);
    }
	
	/**
     * Formatter for the initial log entry, formatting with a timestamp and a message.
     */
	private static class MyLogFormatterInitial extends Formatter {
	    @Override
	    public String format(LogRecord record) {
	        // Custom format: Timestamp Message
	        return getCurrentTimeStamp() + " " + record.getMessage() + System.lineSeparator();
	    }
	}

	/**
     * The standard formatter for logging, with optional level display (and no timestamps).
     */
	private static class MyLogFormatter extends Formatter {
		private boolean showLevel = true;
		
		public MyLogFormatter(boolean showLevel) {
			this.showLevel = showLevel;
		}

		@Override
	    public String format(LogRecord record) {
			String msg = "";
			if (this.showLevel) {
				// Custom format: Log Level: Message
				msg = record.getLevel() + ": " + record.getMessage() + System.lineSeparator();
			}
			else {
				// Custom format: Message
				msg = record.getMessage() + System.lineSeparator();
			}
			return msg;
	    }
	}

}
