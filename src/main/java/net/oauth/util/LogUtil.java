package net.oauth.util;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;

public class LogUtil {
	
	public static String printStackTrace(boolean isFullTrace, Throwable e, String separator, int maxLineCount) {
		
		if (!isFullTrace) {
			maxLineCount = 20;
		}
		StringBuilder sb = new StringBuilder();
		sb.append(e.toString());
		sb.append(separator);
		StackTraceElement[] trace = e.getStackTrace();
		int count = (maxLineCount > trace.length) ? trace.length : maxLineCount;
		for (int i = 0; i < count; i++) {
			sb.append("\tat " + trace[i] + separator);
		}

		Throwable cause = e.getCause();
		if (cause != null) {
			sb.append("Caused by: ");
			if (isFullTrace) {
				sb.append(printStackTrace(isFullTrace, cause, separator, maxLineCount));
			} else {
				sb.append(cause.toString());
			}
		}
		return sb.toString();
	}
	
	public static String printStackTrace(Throwable e) {
		return printStackTrace(e, "\r\n");
	}
	
	public static String printStackTrace(Throwable e, String separator) {
		
		return printStackTrace(true, e, separator, 0);
	}
	
	public static String getCollectionString(Collection<String> inputs){
        StringBuilder stringBuilder = new StringBuilder();
        if(null != inputs && !inputs.isEmpty()){
            for (String input : inputs){
                stringBuilder.append(input);
                stringBuilder.append(",");
            }
        }
        return stringBuilder.toString();
	}
	
	public static String printStackTrace(HttpServletRequest request, Throwable e) {
		StringBuilder sb = new StringBuilder();
		sb.append("Error:");
		sb.append(request.getRequestURI());
		sb.append(",");
		sb.append(LogUtil.printStackTrace(e));
		return sb.toString();
	}
}
