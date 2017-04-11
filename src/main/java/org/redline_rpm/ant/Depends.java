package org.redline_rpm.ant;

import org.apache.tools.ant.types.EnumeratedAttribute;

import static org.redline_rpm.header.Flags.EQUAL;
import static org.redline_rpm.header.Flags.GREATER;
import static org.redline_rpm.header.Flags.LESS;
import static org.redline_rpm.header.Flags.SCRIPT_POST;
import static org.redline_rpm.header.Flags.SCRIPT_POSTTRANS;
import static org.redline_rpm.header.Flags.SCRIPT_POSTUN;
import static org.redline_rpm.header.Flags.SCRIPT_PRE;
import static org.redline_rpm.header.Flags.SCRIPT_PRETRANS;
import static org.redline_rpm.header.Flags.SCRIPT_PREUN;

/**
 * Object describing a dependency on a
 * particular version of an RPM package.
 */
public class Depends {

	protected String name;
	protected String version = "";
	protected int comparison = 0;
	protected int scopeFlag = 0;

	public void setName( String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setComparison( ComparisonEnum comparisonEnum) {
		String comparisonValue = comparisonEnum.getValue();
		if ("equal".equals(comparisonValue)) {
			this.comparison = EQUAL;
		} else if ("greater".equals(comparisonValue)) {
			this.comparison = GREATER;
		} else if ("greater|equal".equals(comparisonValue)) {
			this.comparison = GREATER | EQUAL;
		} else if ("less".equals(comparisonValue)) {
			this.comparison = LESS;
		} else { // must be ( comparisonValue.equals( "less|equal"))
			this.comparison = LESS | EQUAL;
		}
	}

	public int getComparison() {
		if ( 0 == comparison && 0 < version.length()) {
			return GREATER | EQUAL;
		}
		if ( 0 == version.length()) {
			return 0;
		}
		return this.comparison;
	}

	public int getFlags() {
		return getComparison() | scopeFlag;
	}

	public void setScope(String scope) {
		scopeFlag = 0;
		if ( scope != null && scope.length() > 0) {
			for ( String scopeValue : scope.split(",")) {
				scopeFlag = Scope.valueOf(scopeValue.trim()).getFlag();
			}
		}
	}

	public void setVersion( String version) {
		if ( version != null && version.length() > 0) {
			try {
				Integer.parseInt(version.substring(0,1));
			} catch ( NumberFormatException ex) {
				throw new IllegalArgumentException("version [" + version
						+ "] does not start with a digit");
			}
		}
		this.version = version;
	}

	public String getVersion() {
		return version;
	}

	/**
	 * Enumerated attribute with the values "equal", "greater", "greater|equal", "less" and "less|equal".
	 */
	public static class ComparisonEnum extends EnumeratedAttribute {
		public String[] getValues() {
			return new String[] {"equal", "greater", "greater|equal", "less", "less|equal"};
		}
	}

	/**
	 * Values supported for Requires(scope) spec file tag.
	 */
	private static enum Scope {
		pre(SCRIPT_PRE),
		post(SCRIPT_POST),
		preun(SCRIPT_PREUN),
		postun(SCRIPT_POSTUN),
		pretrans(SCRIPT_PRETRANS),
		posttrans(SCRIPT_POSTTRANS);

		private final int flag;

		private Scope(final int flag) {
			this.flag = flag;
		}

		public int getFlag() {
			return flag;
		}
	}
}
