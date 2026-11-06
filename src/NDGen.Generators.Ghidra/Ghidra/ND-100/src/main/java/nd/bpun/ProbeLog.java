/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nd.bpun;

import java.util.Locale;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.Msg;

/**
 * Logs why an ND loader accepted or rejected a file during Ghidra's format probe.
 *
 * <p>Ghidra asks EVERY loader about EVERY file being imported, and a rejected
 * loader simply does not appear in the import dialog's Format list. Without a log
 * line there is no way to tell why, for example, a .BPUN file is offered only as
 * "Raw binary". So every probe calls {@link #reject} with the reason at the point
 * it gives up, and this class writes it to Ghidra's log ({@code application.log} in the user's Ghidra settings folder, and
 * the Ghidra console).</p>
 *
 * <p>Level rule, to keep the log readable:</p>
 * <ul>
 * <li>Rejected, and the file name has this loader's own extension (e.g. a .BPUN
 *     file rejected by the BPUN loader): INFO. That is the case someone is
 *     debugging.</li>
 * <li>Rejected, any other file (an ELF being checked by the BPUN loader, say):
 *     DEBUG. Still in application.log, but not shouted.</li>
 * </ul>
 */
final class ProbeLog {

	private ProbeLog() {
	}

	/**
	 * Logs why a loader rejected a file, and returns false so a probe can write
	 * {@code return reject(p, "why");} at the point of rejection.
	 *
	 * @param loader     the loader doing the probe (used as the log source)
	 * @param loaderName short name for the message, e.g. "BPUN"
	 * @param provider   the file being probed (only its name is used)
	 * @param reason     plain description of why the file is not this format
	 * @param extensions lower-case file extensions this loader owns, without dot
	 * @return always false
	 */
	static boolean reject(Object loader, String loaderName, ByteProvider provider,
			String reason, String... extensions) {
		String file = fileName(provider);
		String msg = loaderName + " loader: REJECTED " + file + " - " + reason;
		if (hasExtension(file, extensions)) {
			Msg.info(loader, msg);
		}
		else {
			Msg.debug(loader, msg);
		}
		return false;
	}

	private static String fileName(ByteProvider provider) {
		String name = provider.getName();
		return name == null ? "(unnamed file)" : name;
	}

	private static boolean hasExtension(String file, String[] extensions) {
		String lower = file.toLowerCase(Locale.ROOT);
		for (int i = 0; i < extensions.length; i++) {
			if (lower.endsWith("." + extensions[i])) {
				return true;
			}
		}
		return false;
	}
}
